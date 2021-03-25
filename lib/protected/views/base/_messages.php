<!--  Messages-->
    <?php if(Yii::app()->user->hasFlash('error')):  ?>
        <div id="message" class="message animated fadeIn flash-error">
            <i class="material-icons">error</i>
            <button class="btn btn-close">Dismiss</button>
            <p><?php echo Yii::app()->user->getFlash('error'); ?></p>
        </div>
    <?php endif;?>
    <?php if(Yii::app()->user->hasFlash('note')):  ?>
        <div id="message" class="message animated fadeIn flash-notice">
            <i class="material-icons">error_outline</i>
            <button class="btn btn-close">Dismiss</button>
            <p><?php echo Yii::app()->user->getFlash('note'); ?></p>
        </div>
    <?php endif;?>
    <?php if(Yii::app()->user->hasFlash('success')):  ?>
        <div id="message" class="message animated fadeIn flash-success">
            <i class="material-icons">thumb_up</i>
            <button class="btn btn-close">Dismiss</button>
            <p><?php echo Yii::app()->user->getFlash('success'); ?></p>
        </div>
    <?php endif;?>
<!--// Messages-->