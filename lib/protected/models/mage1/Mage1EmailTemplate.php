<?php

/**
 * This is the model class for table "core_email_template".
 *
 * The followings are the available columns in table 'core_email_template':
 * @property string $template_id
 * @property string $template_code
 * @property string $template_text
 * @property string $template_styles
 * @property string $template_type
 * @property string $template_subject
 * @property string $template_sender_name
 * @property string $template_sender_email
 * @property string $added_at
 * @property string $modified_at
 * @property string $orig_template_code
 * @property string $orig_template_variables
 */
class Mage1EmailTemplate extends Mage1ActiveRecord
{
	/**
	 * @return string the associated database table name
	 */
	public function tableName()
	{
		return '{{core_email_template}}';
	}

	/**
	 * @return array validation rules for model attributes.
	 */
	public function rules()
	{
		// NOTE: you should only define rules for those attributes that
		// will receive user inputs.
		return array(
			array('template_code, template_text, template_subject', 'required'),
			array('template_code', 'length', 'max'=>150),
			array('template_type', 'length', 'max'=>10),
			array('template_subject, template_sender_name, template_sender_email, orig_template_code', 'length', 'max'=>200),
			array('template_styles, added_at, modified_at, orig_template_variables', 'safe')
		);
	}

	/**
	 * Returns the static model of the specified AR class.
	 * Please note that you should have this exact method in all your CActiveRecord descendants!
	 * @param string $className active record class name.
	 * @return Mage1EmailTemplate the static model class
	 */
	public static function model($className=__CLASS__)
	{
		return parent::model($className);
	}
}
