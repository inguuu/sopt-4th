var express = require("express");
var router = express.Router();

const crypto = require('crypto-promise');

const defaultRes = require("../../module/utils/utils");
const statusCode = require("../../module/utils/statusCode");
const resMessage = require("../../module/utils/responseMessage");
const db = require("../../module/pool");

router.get("/", async (req, res) => {
  const getAllBoardQuery = "SELECT boardIdx,title,content,writer,writetime FROM board";
  const getAllBoardResult = await db.queryParam_None(getAllBoardQuery);

  if (!getAllBoardResult) {
    //쿼리문이 실패했을 때
    res.status(200).send(defaultRes.successFalse( statusCode.DB_ERROR,  resMessage.BOARD_SELECT_FAIL ) );
  } else {
    //쿼리문이 성공했을 때
    res .status(200).send(defaultRes.successTrue( statusCode.OK,  resMessage.BOARD_SELECT_SUCCESS, getAllBoardResult )  );
  }
});
router.get("/:idx", async (req, res) => {
 
  const selectBoardQuery = ' SELECT boardIdx,title,content,writer,writetime FROM board WHERE boardIdx= ? ';
  const selectBoardResult = await db.queryParam_Parse(selectBoardQuery, req.params.idx);
  if (!selectBoardResult) {
    //쿼리문이 실패했을 때
    res.status(200).send(defaultRes.successFalse( statusCode.DB_ERROR,  resMessage.BOARD_SELECT_FAIL ) );
  } else {
    //쿼리문이 성공했을 때
    if(selectBoardResult[0]==null){
      console.log("boardId와 일치하는 게시글 없음");
      res .status(200).send(defaultRes.successFalse( statusCode.NO_CONTENT,  resMessage.NOT_FOUND_BOARDID ));
    }else{
      res .status(200).send(defaultRes.successTrue( statusCode.OK,  resMessage.BOARD_SELECT_SUCCESS, selectBoardResult ));
    }
   
  }
});

router.post('/', async(req, res) => {
  if(!req.body.title||!req.body.content||!req.body.boardPw||!req.body.writer){
    console.log("제목, 내용, 게시물 비밀번호, 작성자를 모두 입력하세요");
    res.status(200).send(defaultRes.successFalse(statusCode.OK, resMessage.ENTER_ALL));
  }else{
    const insertBoardQuery = 'INSERT INTO board (writer, title, content, writetime, boardPw, salt) VALUES (?,?,?,?,?,?)';
 
    const buf = await crypto.randomBytes(64);
    const salt= buf.toString('base64');
    const hashedBoardPw= await crypto.pbkdf2(req.body.boardPw.toString(),salt,1000, 32, 'SHA512');
  
    const insertBoardResult = await db.queryParam_Parse(insertBoardQuery, 
      [req.body.writer, req.body.title, req.body.content,new Date().toISOString() ,hashedBoardPw.toString('base64'),salt]);
  
    if (!insertBoardResult) {
        res.status(200).send(defaultRes.successFalse(statusCode.DB_ERROR, resMessage.BOARD_INSERT_FAIL));
    } else { //쿼리문이 성공했을 때
  
       res.status(200).send(defaultRes.successTrue(statusCode.OK, resMessage.BOARD_INSERT_SUCCESS));
    }
  }
  
});

router.delete("/", async (req, res) => {
  const selectBoardQuery ='SELECT *FROM board WHERE boardIdx= ?';
  const selectBoardResult=await db.queryParam_Parse(selectBoardQuery, req.body.boardIdx);
  
  if(selectBoardResult[0]==null){
    console.log("boardId와 일치하는 게시글 없음");
    res.status(200).send(defaultRes.successFalse( statusCode.NO_CONTENT, resMessage.NOT_FOUND_BOARDID ) );
  }else{
    const salt= selectBoardResult[0].salt;
    const hashedEnterPw= await crypto.pbkdf2(req.body.boardPw.toString(),salt,1000, 32, 'SHA512');
    
    if(selectBoardResult[0].boardPw==hashedEnterPw.toString('base64')){
      const deleteBoardQuery = 'DELETE FROM board WHERE boardIdx= ? ';
      const deleteBoardResult = await db.queryParam_Parse(deleteBoardQuery, req.body.boardIdx);
      if (!deleteBoardResult) {
        //DELETE쿼리문이 실패했을 때
        res.status(200).send(defaultRes.successFalse( statusCode.DB_ERROR,  resMessage.BOARD_DELETE_FAIL ) );
      } else {
        //DELETE쿼리문이 성공했을 때
          res .status(200).send(defaultRes.successTrue( statusCode.OK,  resMessage.BOARD_DELETE_SUCCESS));
      }
    }else{
      res .status(200).send(defaultRes.successTrue( statusCode.OK,  resMessage.BOARD_PASSWORD_ERROR));
    }
    
  }
   
});

module.exports = router;
