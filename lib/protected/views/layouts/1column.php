<?php $this->beginContent('/layouts/main'); ?>
<div id="ub-tool-content">
    <div class="row">
        <div class="col-lg-12">
            <?php $this->widget('UserMenu', array()); ?>
        </div>
    </div>
    <div class="row">
        <div id="main" class="col-lg-12">
            <div id="main-content">
                <?php echo $content; ?>
            </div>
        </div>
    </div>
</div>
<?php $this->endContent(); ?>