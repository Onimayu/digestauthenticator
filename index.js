'use strict';

require('source-map-support').install();

const AWS = require('aws-sdk');
const crypto = require('crypto');
const csvParser = require('csv-parse/lib/sync');
const moment = require('moment-timezone');

moment.tz.setDefault("Asia/Tokyo");

const DYNAMO_REGION = 'ap-northeast-1';
const TABLE_NAME = 'DigestNonce';

const REGEXP = {
  'cResponse': /response="?([a-zA-Z0-9]+)"?/g,
  'nonce': /,\s*nonce="?([a-zA-Z0-9]+)"?/g,
  'cNonce': /cnonce="?([a-zA-Z0-9]+)"?/g,
  'cNc': /nc="?([0-9]+)"?/g,
  'cUri': /uri="?([^"]+)"?/g,
};

const DIGEST_AUTH_DEFAULT_PARAMS = {
  'realm': 'yumemi.jp',
  'qop': 'auth',
  'algorithm': 'MD5',
};

/// ダイジェスト認証用ID/PASSが記載されたJSONマスタファイルを読み込む
const readDigestMaster = async () => {
  return require('./.master/id_pass.json');
};

///Digest認証要求のレスポンスデータを生成する
const createDigestAuthResponse = (authString) => {

  const body = 'Unauthorized';
  return {
    status: '401',
    statusDescription: 'Unauthorized',
    body: body,
    headers: {
      'www-authenticate': [{
        key: 'WWW-Authenticate',
        value: authString
      }]
    }
  };
};

const getNonceFromHeader = (headers) =>{
  let results = new RegExp(REGEXP.nonce).exec(headers.authorization[0].value);
  return (results!=null) ? results[1] : null;
}

/// Digest認証の実施
const doAuthorization = (request, headers, digestauthParam, user, pass) => {

  const cResponse = new RegExp(REGEXP.cResponse).exec(headers.authorization[0].value)[1];
  const nonce = getNonceFromHeader(headers);
  const cNonce = new RegExp(REGEXP.cNonce).exec(headers.authorization[0].value)[1];
  const cNc = new RegExp(REGEXP.cNc).exec(headers.authorization[0].value)[1];
  const cUri = new RegExp(REGEXP.cUri).exec(headers.authorization[0].value)[1];

  const A1 = crypto.createHash('md5').update(`${user}:${digestauthParam.realm}:${pass}`, 'binary').digest('hex');
  const A2 = crypto.createHash('md5').update(request.method + ':' + cUri, 'binary').digest('hex');
  const reResponse = crypto.createHash('md5').update(A1 + `:${nonce}:${cNc}:${cNonce}:${digestauthParam.qop}:` + A2, 'binary').digest('hex');

//  console.log(`cResponse:${cResponse}  /  nonce:${nonce}  /  cNonce:${cNonce}  /  cNc:${cNc}  /  cUri:${cUri}  / A1:${A1}  /  A2:${A2}  / user:${user}  /  pass:${pass}  /  ${cResponse} == ${reResponse}`);

  return cResponse === reResponse;
};

const dynamoPut = async (params) =>{

  const client = new AWS.DynamoDB.DocumentClient({
    "apiVersion": "2012-08-10",
    "region": DYNAMO_REGION,
    "convertEmptyValues":true
  });

  const param = {
    TableName: TABLE_NAME,
    Item: params
  };

  return client.put(param).promise();
}

const dynamoGet = async (key) =>{

  const client = new AWS.DynamoDB.DocumentClient({
    "apiVersion": "2012-08-10",
    "region": DYNAMO_REGION,
    "convertEmptyValues":true
  });

  const param = {
    TableName: TABLE_NAME,
    Key: key
  };

  return client.get(param).promise();
}

/// nonceの保存
const saveNonce = async (nonce) => {

  let now = new moment();

  const params = {
    nonce: nonce,
    TTL: new moment().add(1, "days").unix()
  };

  await dynamoPut(params);
};

/// レスポンス用Digest realmを生成する
let createAuthString = (nonce) => {
  return `Digest realm="${DIGEST_AUTH_DEFAULT_PARAMS.realm}", qop="${DIGEST_AUTH_DEFAULT_PARAMS.qop}", nonce="${nonce}", algorithm=${DIGEST_AUTH_DEFAULT_PARAMS.algorithm}`;
}


/// リクエストヘッダ確認
const checkRequestHeader = async (headers) => {

  let nonce = null;
  try{
    if ( headers.authorization ) {
      // ヘッダあり。2回目以降のチャレンジアクセスとみなす
      nonce = getNonceFromHeader(headers);
      if ( nonce ){
        let dbResult = await dynamoGet({'nonce': nonce});
        nonce = ( dbResult.Item ) ? dbResult.Item.nonce : null;
      }
    }

    if ( nonce === null ){
      // authorizationヘッダがない、またはDigestNonceテーブルにレコードがない
      nonce = crypto.randomBytes(17).toString('hex');
      await saveNonce(nonce);
    }

    return nonce;
  }catch(err){
    console.error("ヘッダ確認中に例外発生:%s", err.stack);
    throw err;
  }
}


/**
 * メイン処理
 * @param request
 * @param headers
 * @returns {Promise<*>}
 */
const doProcess = async (request, headers) => {

  /// IP制限：許可IP
  const ALLOW_IP_ADDRESS = [
    // '39.110.218.156'
  ];

  /// 未認証ディレクトリ定義
  const ALLOW_DIR = [
//    '/hoge/'
  ];

  try {

    // 特定ディレクトリとIPアドレスの場合は認証無し
    console.log(`認証スキップチェックを実施します --> ${request.clientIp} : ${request.uri}`);
    const isAllowIp = ALLOW_IP_ADDRESS.includes(request.clientIp);
    const isAllowDir = ALLOW_DIR.some(e=>{
      const reg = new RegExp(e);
      return reg.test(request.uri);
    });

    if ( isAllowIp === true && isAllowDir === true ){
      console.log(`認証無しリクエストです`);
      return request;
    }
    console.log(`認証スキップチェック --> ${isAllowIp} ${isAllowDir}`);

    console.log("リクエストヘッダを確認し、nonceを生成・取得します");
    let nonce = await checkRequestHeader(headers);
    console.log("リクエストヘッダを確認し、nonceを生成・取得しました(%s)", nonce);

    let authString = createAuthString(nonce);
    // authorizationヘッダが存在しない（チャレンジ要求）
    if ( typeof headers.authorization === 'undefined' ){
      console.log("チャレンジ要求に応答し、処理を終了します");
      return createDigestAuthResponse(authString);
    }

    console.log("Digest認証マスタデータを取得します");
    const master = require('./.master/id_pass.json');
    console.log("Digest認証マスタデータを取得しました");

    console.log("Digest認証を開始します");
    let authResult = false;
    for ( let i = 0 ; i < master.length ; i++ ){
      authResult = doAuthorization(request, headers, DIGEST_AUTH_DEFAULT_PARAMS, master[i]['user'], master[i]['password']);
      if ( authResult === true ){
        break;
      }
    }

    if ( authResult === false ){
      console.log("Digest認証失敗。終了します");
      return createDigestAuthResponse(authString);
    }
    console.log("Digest認証成功。終了します");

    return request;
  } catch (err) {
    console.error("Digest認証中に例外が発生しました:%s", err.stack);
    throw err;
  }
};

exports.handler = async (event, context, callback) => {

  const request = event.Records[0].cf.request;
  const headers = request.headers;

  try {
    callback(null, await doProcess(request, headers));
  } catch (err) {
    throw err;
  }
};
