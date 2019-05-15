var express = require('express');
var router = express.Router();

const defaultRes = require('../../module/utils/utils');
const statusCode = require('../../module/utils/statusCode');
const resMessage = require('../../module/utils/responseMessage')
const db = require('../../module/pool'); //createPool을 해서 여러 개의 connection을 가져온 상태 

//모듈에 있는 함수가 async/await를 사용하여 promise-mysql을 await하기 때문에
//해당 모듈을 사용하는 함수는 async/await 문법을 사용하는 함수여야 합니다.
//때문에 콜백함수들이 모두 async 입니다.
router.get('/', async(req, res) => {
    const getAllUserQuery = 'SELECT * FROM membership';
    //쿼리문에 ? 값이 아무것도 없을 때 queryParam_None 사용
    const getAllUserResult = await db.queryParam_None(getAllUserQuery);

    //쿼리문의 결과가 실패이면 null을 반환한다
    if (!getAllUserResult) { //쿼리문이 실패했을 때
        res.status(200).send(defaultRes.successFalse(statusCode.DB_ERROR, resMessage.MEMBERSHIP_SELECT_FAIL));
    } else { //쿼리문이 성공했을 때
        res.status(200).send(defaultRes.successTrue(statusCode.OK, resMessage.MEMBERSHIP_SELECT_SUCCESS, getAllUserResult));
    }
});

router.post('/', async(req, res) => {
    const insertWomanQuery = 'INSERT INTO membership (name, gender, part, univ) VALUES (?, ?, ?, ?)';
    const insertWomanResult = await db.queryParam_Parse(insertWomanQuery, [req.body.name, req.body.gender, req.body.part, req.body.univ]);

    if (!insertWomanResult) {
        res.status(200).send(defaultRes.successFalse(statusCode.DB_ERROR, resMessage.MEMBERSHIP_INSERT_FAIL));
    } else { //쿼리문이 성공했을 때
        res.status(200).send(defaultRes.successTrue(statusCode.OK, resMessage.MEMBERSHIP_INSERT_SUCCESS));
    }
});

router.post('/transaction', async(req, res) => {
    const insertMenQuery = 'INSERT INTO membership (name, gender, part, univ) VALUES (?, ?, ?, ?)';
    const updatePartQuery = 'UPDATE membership SET part = ? WHERE userIdx = ?';

    //트렌젝션 처리를 하기 위한 Transaction 메소드 모듈
    const insertTransaction = await db.Transaction(async(connection) => {
        //Transaction 모듈에서 나온 connection으로 쿼리를 날림
        const insertMenResult = await connection.query(insertMenQuery, [req.body.name, req.body.gender, req.body.part, req.body.univ]);
        const userIdx = insertMenResult.insertId; //삽입된 유저의 userIdx를 가져옴
        const updatePartResult = await connection.query(updatePartQuery, ["android", userIdx]);
    });

    //실패했을 때 모듈 안에서 자동적으로 rollback을 해주고, 성공했을 때 commit을 해주기 때문에 따로 안해줘도 됨
    //저는 지금 에러처리를 몇단계 스킵햇지만 여러분은 여러분 나름대로 에러처리 꼭 해주세요.
    if (!insertTransaction) {
        res.status(200).send(defaultRes.successFalse(statusCode.OK, resMessage.MEMBERSHIP_TRANSAC_FAIL));
    } else {
        res.status(200).send(defaultRes.successTrue(statusCode.OK, resMessage.MEMBERSHIP_TRANSAC_SUCCESS));
    }

});

module.exports = router;