var express = require('express');
var router = express.Router();

const crypto = require('crypto-promise');

const defaultRes = require('../../module/utils/utils');
const statusCode = require('../../module/utils/statusCode');
const resMessage = require('../../module/utils/responseMessage')
const db = require('../../module/pool');

router.post('/', async(req, res) => {
    const selectUserQuery = 'SELECT * FROM user WHERE id = ?'
    const selectUserResult = await db.queryParam_Parse(selectUserQuery, req.body.id);
    //console.log(selectUserResult[0])//유저 정보

    if(selectUserResult[0]==null){//id가 존재하지 않으면
        console.log("id가 존재하지 않음");
        res.status(200).send(defaultRes.successFalse(statusCode.OK, resMessage.NOT_CORRECT_USERINFO));
    }else{
        const salt= selectUserResult[0].salt;
        const hashedEnterPw= await crypto.pbkdf2(req.body.password.toString(),salt,1000, 32, 'SHA512');
        
        if(selectUserResult[0].password==hashedEnterPw.toString('base64')){
            res.status(200).send(defaultRes.successTrue(statusCode.OK, resMessage.SIGNIN_SUCCESS,selectUserResult[0].userIdx));
        }else{
            console.log("비밀번호가 존재하지 않음");
            res.status(200).send(defaultRes.successFalse(statusCode.OK, resMessage.NOT_CORRECT_USERINFO));
        }
    }
    
});

module.exports = router;
