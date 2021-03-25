<!DOCTYPE html>
<html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en" lang="en">
<head>
    <title><?php echo CHtml::encode($this->pageTitle); ?></title>
	<meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
	<meta name="language" content="en" />
    <link rel="shortcut icon" href="<?php echo Yii::app()->request->baseUrl; ?>/css/images/favicon.ico">
    <link rel="stylesheet" href="<?php echo Yii::app()->request->baseUrl; ?>/css/bootstrap/css/bootstrap.min.css">
    <link rel="stylesheet" href="<?php echo Yii::app()->request->baseUrl; ?>/css/bootstrap/css/bootstrap-theme.min.css">
    <link rel="stylesheet" type="text/css" href="<?php echo Yii::app()->request->baseUrl; ?>/css/main.css" />
    <script type="text/javascript" src="<?php echo Yii::app()->request->baseUrl; ?>/js/jquery.min.js"></script>
    <script type="text/javascript" src="<?php echo Yii::app()->request->baseUrl; ?>/js/bootstrap.min.js"></script>
    <script type="text/javascript" src="<?php echo Yii::app()->request->baseUrl; ?>/js/script.js"></script>
    <!-- VENDORS -->
    <link rel="stylesheet" href="//fonts.googleapis.com/icon?family=Material+Icons">
</head>

<body>

<div id="page" class="container">

    <?php echo $content; ?>

</div>

<div id="footer">
<div class="container">
    <div class="row">
        <div class="col-md-6 copyright">Copyright &copy; <?php echo date('Y'); ?> by <a href="//www.ubertheme.com/" target="_blank">UberTheme</a>. All Rights Reserved. <br />
        </div>
        <div class="col-md-6" id="report-bugs">
            <a target="_blank" href="//www.ubertheme.com/ask-question/" title="<?php echo Yii::t('frontend', 'Report Bugs/Ask a question')?>">
                <strong><?php echo Yii::t('frontend', 'Report Bugs/Ask a question')?></strong>
            </a>
        </div>
    </div>
</div>
</div>

</body>

</html>