<?php

/**
 * This is the model class for table "{{ub_migrate_map_step_5_product_download}}".
 *
 * The followings are the available columns in table '{{ub_migrate_map_step_5_product_download}}':
 * @property string $id
 * @property string $entity_name
 * @property string $m1_id
 * @property string $m2_id
 * @property string $m2_model_class
 * @property string $m2_key_field
 * @property integer $can_reset
 * @property string $created_time
 * @property integer $offset
 */
class MappingStep5ProductDownload extends CActiveRecord
{
	/**
	 * @return string the associated database table name
	 */
	public function tableName()
	{
		return '{{ub_migrate_map_step_5_product_download}}';
	}

	/**
	 * Returns the static model of the specified AR class.
	 * Please note that you should have this exact method in all your CActiveRecord descendants!
	 * @param string $className active record class name.
	 * @return MappingStep5ProductDownload the static model class
	 */
	public static function model($className=__CLASS__)
	{
		return parent::model($className);
	}
}
