<?php

/**
 * This is the model class for table "newsletter_queue".
 *
 * The followings are the available columns in table 'newsletter_queue':
 * @property string $queue_id
 * @property string $template_id
 * @property integer $newsletter_type
 * @property string $newsletter_text
 * @property string $newsletter_styles
 * @property string $newsletter_subject
 * @property string $newsletter_sender_name
 * @property string $newsletter_sender_email
 * @property string $queue_status
 * @property string $queue_start_at
 * @property string $queue_finish_at
 */
class Mage1NewsletterQueue extends Mage1ActiveRecord
{
	/**
	 * @return string the associated database table name
	 */
	public function tableName()
	{
		return '{{newsletter_queue}}';
	}

	/**
	 * @return array validation rules for model attributes.
	 */
	public function rules()
	{
		// NOTE: you should only define rules for those attributes that
		// will receive user inputs.
		return array(
			array('newsletter_type', 'numerical', 'integerOnly'=>true),
			array('template_id, queue_status', 'length', 'max'=>10),
			array('newsletter_subject, newsletter_sender_name, newsletter_sender_email', 'length', 'max'=>200),
			array('newsletter_text, newsletter_styles, queue_start_at, queue_finish_at', 'safe')
		);
	}

	/**
	 * Returns the static model of the specified AR class.
	 * Please note that you should have this exact method in all your CActiveRecord descendants!
	 * @param string $className active record class name.
	 * @return Mage1NewsletterQueue the static model class
	 */
	public static function model($className=__CLASS__)
	{
		return parent::model($className);
	}
}
