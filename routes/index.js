var express = require("express");
var router = express.Router();

router.use("/training", require("./training/index"));
router.use("/homework", require("./homework/index"));
module.exports = router;
