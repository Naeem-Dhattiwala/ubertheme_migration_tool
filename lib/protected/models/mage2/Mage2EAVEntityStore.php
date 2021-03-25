<?php

/**
 * This is the model class for table "eav_entity_store".
 *
 * The followings are the available columns in table 'eav_entity_store':
 * @property integer $entity_store_id
 * @property integer $entity_type_id
 * @property integer $store_id
 * @property string $increment_prefix
 * @property string $increment_last_id
 */
class Mage2EAVEntityStore extends Mage2ActiveRecord
{
	/**
	 * @return string the associated database table name
	 */
	public function tableName()
	{
		return '{{eav_entity_store}}';
	}

	/**
	 * Returns the static model of the specified AR class.
	 * Please note that you should have this exact method in all your CActiveRecord descendants!
	 * @param string $className active record class name.
	 * @return Mage2EAVEntityStore the static model class
	 */
	public static function model($className=__CLASS__)
	{
		return parent::model($className);
	}
}
