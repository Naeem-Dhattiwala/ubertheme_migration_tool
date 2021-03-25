<?php
/**
 * Copyright © Magento, Inc. All rights reserved.
 * See COPYING.txt for license details.
 */
namespace Ubertheme\Ubdatamigration\Plugin\Customer\Model;

use Magento\Customer\Model\CustomerRegistry;
use Magento\Customer\Model\ResourceModel\Customer as CustomerResourceModel;
use Magento\Framework\Encryption\EncryptorInterface as Encryptor;
use Magento\Customer\Model\Authentication;

/**
 * Plugin for Authentication
 */
class AuthenticationPlugin
{
    /**
     * @var CustomerRegistry
     */
    private $customerRegistry;

    /**
     * @var CustomerResourceModel
     */
    private $customerResourceModel;

    /**
     * @var Encryptor
     */
    private $encryptor;

    /**
     * @param CustomerRegistry $customerRegistry
     * @param CustomerResourceModel $customerResourceModel
     * @param Encryptor $encryptor
     */
    public function __construct(
        CustomerRegistry $customerRegistry,
        CustomerResourceModel $customerResourceModel,
        Encryptor $encryptor
    ) {
        $this->customerRegistry = $customerRegistry;
        $this->customerResourceModel = $customerResourceModel;
        $this->encryptor = $encryptor;
    }

    /**
     * Replace customer password hash in case it is Bcrypt algorithm
     *
     * @param Authentication $subject
     * @param $customerId
     * @param $password
     * @throws \Magento\Framework\Exception\NoSuchEntityException
     */
    public function beforeAuthenticate(
        Authentication $subject,
        $customerId,
        $password
    ) {
        $customerSecure = $this->customerRegistry->retrieveSecureData($customerId);
        $hash = $customerSecure->getPasswordHash();
        if ($this->isBcrypt($hash) && $this->verify($password, $hash)) {
            $this->customerRegistry->remove($customerId);
            $hash = $this->encryptor->getHash($password, true);
            $this->customerResourceModel->getConnection()->update(
                $this->customerResourceModel->getTable('customer_entity'),
                [
                    'password_hash' => $hash
                ],
                $this->customerResourceModel->getConnection()->quoteInto('entity_id = ?', $customerId)
            );
        }
    }

    /**
     * Verify password
     *
     * @param string $password
     * @param string $hash
     * @return bool
     */
    public function verify($password, $hash)
    {
        return password_verify($password, $hash);
    }

    /**
     * Check if hash is Bcrypt algorithm
     *
     * @param string $hash
     * @return bool
     */
    public function isBcrypt($hash)
    {
        if (stripos($hash, '$2y$') === 0) {
            return true;
        }
        return false;
    }
}
