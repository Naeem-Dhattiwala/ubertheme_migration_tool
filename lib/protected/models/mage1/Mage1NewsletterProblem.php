<?php

/**
 * This is the model class for table "newsletter_problem".
 *
 * The followings are the available columns in table 'newsletter_problem':
 * @property string $problem_id
 * @property string $subscriber_id
 * @property string $queue_id
 * @property string $problem_error_code
 * @property string $problem_error_text
 */
class Mage1NewsletterProblem extends Mage1ActiveRecord
{
	/**
	 * @return string the associated database table name
	 */
	public function tableName()
	{
		return '{{newsletter_problem}}';
	}

	/**
	 * @return array validation rules for model attributes.
	 */
	public function rules()
	{
		// NOTE: you should only define rules for those attributes that
		// will receive user inputs.
		return array(
			array('subscriber_id, queue_id, problem_error_code', 'length', 'max'=>10),
			array('problem_error_text', 'length', 'max'=>200)
		);
	}

	/**
	 * Returns the static model of the specified AR class.
	 * Please note that you should have this exact method in all your CActiveRecord descendants!
	 * @param string $className active record class name.
	 * @return Mage1NewsletterProblem the static model class
	 */
	public static function model($className=__CLASS__)
	{
		return parent::model($className);
	}
}
