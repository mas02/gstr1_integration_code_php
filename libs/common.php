<?php
error_reporting(E_ALL);
ini_set('display_errors', 1);
include_once 'constants.php';
include_once 'Security.php';

class common {

    /**
     * getRandomCode Method
     * 
     * @param $length
     * @param $type
     * @return string
     */
    public function getRandomCode($length, $type = null) {
        // Random characters
        if ($type == 'alphabetic') {
            $keys = array_merge(range('a', 'z'), range('A', 'Z'));
        } elseif ($type == 'numeric') {
            $characters = array("0", "1", "2", "3", "4", "5", "6", "7", "8", "9");
            $keys = array_merge(range(0, 9));
        } else {
            $keys = array_merge(range(0, 9), range('a', 'z'), range('A', 'Z'));
        }
        // set the array
        $key = '';
        for ($i = 0; $i < $length; $i++) {
            $key .= $keys[array_rand($keys)];
        }
        // display random key
        return $key;
    }

    /**
     * Function used to encrypt data with GSP app-key
     * @param string $data
     * @param type $appKey
     * @return string
     */
    public function EncryptWithAppKey($data, $appKey) {
        $iv = $appKey; // pass app-key as $iv
        $blocksize = 16;
        $pad = $blocksize - (strlen($data) % $blocksize);
        $data = $data . str_repeat(chr($pad), $pad);
        return bin2hex(mcrypt_encrypt(MCRYPT_RIJNDAEL_128, $appKey, $data, MCRYPT_MODE_CBC, $iv));
    }

    /**
     * Encrypt App-key with GSP public key
     */
    public function encryptAspPubliKey($data) {
        $fp = fopen(__dir__ . "/files/server.crt", "r");
        $public = fread($fp, 8192);
        fclose($fp);
        openssl_public_encrypt($data, $encryptedData, $public, OPENSSL_PKCS1_PADDING);
        // Return encrypted app-key
        return base64_encode($encryptedData);
    }
    
    /**
     * This method used to encrypt data with EK
     *
     */
    public function encryptData($value, $ek) {
        $key = base64_decode($ek);
        $response['error'] = false;
        $response['data'] = Security::encrypt($value, $key);

        return $response;
    }
    
    /**
     * decryptData Method
     * @param string $data
     * @param string $appkey
     * @return string
     */
    public function decryptData($data, $appkey) {
        $value = $data;
        $key = base64_decode($appkey); //16 Character Key
        return Security::decrypt($value, $key);
    }


     /**
     * This method used to encrypt OTP which is passed to GST system
     *
     */
    public function encryptOTP($value, $appkey) {
        if ($value == '' || $appkey == '') {
            $response['error'] = true;
            $response['message'] = 'params required in otp encryption';
            return $response;
        }
        $key = base64_decode($appkey);
        $response['error'] = false;
        $response['data'] = Security::encrypt($value, $key);
        
        return $response;
    }

    public function genHashHmac256($data, $ek) {
    return base64_encode(hash_hmac('sha256', $data, $ek, true));
}

    /**
     * getAccessToken method
     * 
     * Method used to get access-token from GSP(Masters India)
     * @param type $JsonAspUser
     * @param type $appKey
     * @return string
     */
    public function getAccessToken() {
       // echo "<strong>Authentication from Masters India Side</strong><br><br><br>";
        //fetch GSP user data
        $aspUserInfo = unserialize(accessTokenInfo);
        $aspUserData['username'] = $aspUserInfo['username'];
        $aspUserData['password'] = $aspUserInfo['password'];
        $aspUserData['client_id'] = $aspUserInfo['client_id'];
        $aspUserData['client_secret'] = $aspUserInfo['client_secret'];
        $aspUserData['grant_type'] = $aspUserInfo['grant_type'];
        $JsonAspUser = json_encode($aspUserData);
        //generate app-key of 16 character length
        $appKey = $this->getRandomCode(16);
        //encrypt data with app-key
        $encryptedWithAppKey = $this->EncryptWithAppKey($JsonAspUser, $appKey);
        //encrypt app-key with Public key
        $encryptedWithPub = $this->encryptAspPubliKey($appKey);
        if ($encryptedWithPub) {
            //prepare data for access token
            $EncryptedData['credentials_data'] = $encryptedWithAppKey;
            $EncryptedData['app_key'] = $encryptedWithPub;
            //echo "<strong>Request Header</strong><br><br>";
            $HeaderOption = array('Content-Type: application/json');
            
            $json_encode_data = json_encode($EncryptedData);
            //send request to get access token
            $GSPApiUrl = unserialize(requestUrl);
            $url = $GSPApiUrl['access_token'];
            $result = $this->sendGSPRequest($url, $json_encode_data, 'POST');
            if (isset($result) && isset($result->accessToken)) {
                $response['error'] = false;
                $response['access_token'] = $result->accessToken;
                $response['expire'] = $result->expires_in;
                $response['app_key'] = $appKey;
            } else{
                if (isset($result->error->error_cd)) {
                    if (isset($result->error->error_description->error)) {
                        $msg = $result->error->error_description->error_description;
                    }elseif(isset($result->error->error_description)) {
                        $msg = $result->error->error_description;
                    } else {
                        $msg = $result->error_description;
                    }
                }else{
                    $msg = "Service not available. Please, try after sometime";
                }
                $response['error'] = true;
                $response['message'] = $msg;
            }
        } else {
            $response['error'] = true;
            $response['message'] = 'Error in encrypting with public key';
        }

        return $response;
    }
    




     /**
     * ewayEncryption method
     * Method used to encrypt app key for E-Inv API
     * @param string $pass
     * @access public
     * @return string
     */
        public function encryption($pass = null) {
        //generate AES 256 App Key
        if ($pass != null || $pass != '') {
            $appKey = base64_encode($pass);
        } else {
            //$appKey = base64_encode(openssl_random_pseudo_bytes(32));
            $randomKey = $this->getRandomCode(32);
            $appKey = base64_encode($randomKey);
        }
        //read gst pem file
         $fp = fopen(__dir__."/PublicKey/GSTN_PublicKey.pem", "r");
        
        $pub_key = fread($fp, 8192);
        fclose($fp);
        //encrypt app key with gstn public key
        openssl_public_encrypt(base64_decode($appKey), $crypttext, $pub_key);
        
        $response['flat_app_key'] = $appKey;
        $response['encrypt_app_key'] = base64_encode($crypttext);

        return $response;
    }
    
   
 /**
     * send otp to the user
     */
    public function OTPRequest($gstUsername,$state,$access_token,$ASP_client_id,$ASP_app_key,$gstin) {
        //print_r($gstUsername);die;
        
        $other_param_data['access_token'] = $access_token;
       
        $other_param_json = json_encode($other_param_data);
        //encrypt data with app-key
        $encryptedWithAppKey = $this->EncryptWithAppKey($other_param_json, $ASP_app_key);
        //prepare user's field data
        $app_key_data = $this->encryption();
        
        $fields['action'] = "OTPREQUEST";
        $fields['username'] = $gstUsername;
        $fields['app_key'] = $app_key_data['encrypt_app_key'];

        $fields['other_parameters'] = $encryptedWithAppKey;

        $data = json_encode($fields);
        $requestUrl = unserialize(requestUrl);
        $url = $requestUrl['auth_url'];
        //send user's header
        $ip = $_SERVER['REMOTE_ADDR'];
        $txn = $this->getRandomCode(16);
        $otherDetail['ip'] = $ip;
        $otherDetail['client-id'] = $ASP_client_id;
        $otherDetail['username'] = $gstUsername;
        $otherDetail['state_cd'] = $state;
        $otherDetail['txn'] = $txn;
        $encodedOtherDetails = json_encode($otherDetail);
        
        $result = $this->sendGSPRequest($url, $data, 'POST', $encodedOtherDetails);
        
        if ($result) {
            if (isset($result->status_cd) && $result->status_cd == 1) {
                $response['flat_app_key'] = $app_key_data['flat_app_key'];
                $response['encrypt_app_key'] = $app_key_data['encrypt_app_key'];
                $response['status'] = $result->status_cd;
                $response['error'] = false;
            } else {
                if (isset($result->error->message)) {
                    $msg = $result->error->message;
                } elseif (isset($result->error->desc)) {
                    $msg = $result->error->desc;
                } elseif (isset($result->message)) {
                    $msg = $result->message;
                } elseif (isset($result->error_msg)) {
                    $msg = $result->error_msg;
                } elseif (isset($result->error->error_cd)) {
                    if (isset($result->error->error_description->error_description)) {
                        $msg = $result->error->error_description->error_description;
                    } elseif (isset($result->error->error_description)) {
                        $msg = $result->error->error_description;
                    }
                } else {
                    $msg = 'Service unavailable. Please try again later';
                }
                $response['error'] = true;
                $response['message'] = $msg;
            }
        } else {
            $response['error'] = true;
            $response['message'] = 'Something goes wrong please try again later';
        }
        return $response;
    }



    /**
     * request to send user's authtoken
     */
    public function authtoken($gstUsername,$state,$access_token,$ASP_client_id,$ASP_app_key,$gstin,$otp,$encryptedAppKey,$flatAppKey) {
        
        $ASP_client_id = $ASP_client_id;
        $ASP_app_key = $ASP_app_key;
        $other_param_data['access_token'] = $access_token;
        
        $other_param_json = json_encode($other_param_data);

        //encrypt data with app-key
        $encryptedWithAppKey = $this->EncryptWithAppKey($other_param_json, $ASP_app_key);

        //prepare user's field data
        $fields['action'] = "AUTHTOKEN";
        $fields['username'] = $gstUsername;
        $fields['app_key'] = $encryptedAppKey;
        //encrypte the otp with flat app key

        $encryptOTP = $this->encryptOTP($otp, $flatAppKey);
        $fields['otp'] = $encryptOTP['data'];        
        $fields['other_parameters'] = $encryptedWithAppKey;
        $data = json_encode($fields);
       
       $GstrApiUrl = unserialize(requestUrl);
       
         $url = $GstrApiUrl['auth_url'];
        $ip = $_SERVER['REMOTE_ADDR'];
        $txn = $this->getRandomCode(16);

        //send user's header
        $otherDetail['ip'] = $ip;
        $otherDetail['client-id'] = $ASP_client_id;
        $otherDetail['username'] = $gstUsername;
        $otherDetail['state_cd'] = $state;
        $otherDetail['txn'] = $txn;
        $encodedOtherDetails = json_encode($otherDetail);
        
        $result = $this->sendGSPRequest($url, $data, 'POST', $encodedOtherDetails);
        
        if ($result) {
            if (isset($result->status_cd) && $result->status_cd == 1) {
                //decrypt sek with app key
                $sek = $result->sek; //temp
                $ek = $this->decryptData($sek, $flatAppKey);
                if ($ek) {
                    $response['error'] = false;
                    $response['sek'] = $result->sek;
                    $response['auth_token'] = $result->auth_token;
                    $response['expiry'] = $result->expiry;
                    //$response['ek'] = $ek;
                } else {
                    $response['error'] = true;
                    $response['message'] = 'Error in decrypting sek'; //temp
                }
            } else {
                if (isset($result->error->message)) {
                    $msg = $result->error->message;
                } elseif (isset($result->error->desc)) {
                    $msg = $result->error->desc;
                } elseif (isset($result->message)) {
                    $msg = $result->message;
                } elseif (isset($result->error_msg)) {
                    $msg = $result->error_msg;
                } elseif (isset($result->error->error_cd)) {
                    if (isset($result->error->error_description->error_description)) {
                        $msg = $result->error->error_description->error_description;
                    } elseif (isset($result->error->error_description)) {
                        $msg = $result->error->error_description;
                    }
                } else {
                    $msg = 'Service unavailable. Please try again later';
                }
                $response['error'] = true;
                $response['message'] = $msg;
            }
        } else {
            $response['error'] = true;
            $response['message'] = 'Service unavailable. Please try again later';
        }

        return $response;
    }



/**
     * request to logout 
     */
    public function gstLogout($gstUsername,$state,$access_token,$ASP_client_id,$ASP_app_key,$gstin,$authtoken,$encryptedAppKey) {
        
        $ASP_client_id = $ASP_client_id;
        $ASP_app_key = $ASP_app_key;
        $other_param_data['access_token'] = $access_token;
        
        $other_param_json = json_encode($other_param_data);

        //encrypt data with app-key
        $encryptedWithAppKey = $this->EncryptWithAppKey($other_param_json, $ASP_app_key);

        //prepare user's field data
        $fields['action'] = "LOGOUT";
        $fields['username'] = $gstUsername;
        $fields['app_key'] = $encryptedAppKey;
        $fields['auth_token'] = $authtoken;        
        $fields['other_parameters'] = $encryptedWithAppKey;
        $data = json_encode($fields);

        $GstrApiUrl = unserialize(requestUrl);
       
        $url = $GstrApiUrl['auth_url'];
        $ip = $_SERVER['REMOTE_ADDR'];
        $txn = $this->getRandomCode(16);

        //send user's header
        $otherDetail['ip'] = $ip;
        $otherDetail['client-id'] = $ASP_client_id;
        $otherDetail['auth_token'] = $authtoken;
        $otherDetail['username'] = $gstUsername;
        $otherDetail['state_cd'] = $state;
        $otherDetail['txn'] = $txn;
        $encodedOtherDetails = json_encode($otherDetail);
        
        $result = $this->sendGSPRequest($url, $data, 'POST', $encodedOtherDetails);
        //print_r($result);//die;
        if ($result) {
            if (isset($result->status_cd) && $result->status_cd == 1) {
                //decrypt sek with app key
                //$sek = $result->sek; //temp
                
                if ($ek) {
                    $response['error'] = false;
                    $response['sek'] = $result->sek;
                    $response['auth_token'] = $result->auth_token;
                    $response['expiry'] = $result->expiry;
                    //$response['ek'] = $ek;
                } else {
                    $response['error'] = true;
                    $response['message'] = 'Error in decrypting sek'; //temp
                }
            } else {
                if (isset($result->error->message)) {
                    $msg = $result->error->message;
                } elseif (isset($result->error->desc)) {
                    $msg = $result->error->desc;
                } elseif (isset($result->message)) {
                    $msg = $result->message;
                } elseif (isset($result->error_msg)) {
                    $msg = $result->error_msg;
                } elseif (isset($result->error->error_cd)) {
                    if (isset($result->error->error_description->error_description)) {
                        $msg = $result->error->error_description->error_description;
                    } elseif (isset($result->error->error_description)) {
                        $msg = $result->error->error_description;
                    }
                } else {
                    $msg = 'Service unavailable. Please try again later';
                }
                $response['error'] = true;
                $response['message'] = $msg;
            }
        } else {
            $response['error'] = true;
            $response['message'] = 'Service unavailable. Please try again later';
        }

        return $response;
    }


/*
    Save GSTR Data
*/

    public function saveGSTRData($gst_username,$state,$access_token,$ASP_client_id,$ASP_app_key,$gstin,$sek,$encryptedAppKey,$flat_app_key,$data_json,
    $gstrType,$returnPeriod,$auth_token) {
        
               
        $ASP_client_id = $ASP_client_id;
        $ASP_app_key = $ASP_app_key;
        $other_param_data['access_token'] = $access_token;       
        $other_param_json = json_encode($other_param_data);
        //encrypt data with app-key
        $encryptedWithAppKey = $this->EncryptWithAppKey($other_param_json, $ASP_app_key);
       
        //get $ek
        $ek = $this->decryptData($sek, $flat_app_key);
        //encrypt data with EK
        $enc = $this->encryptData(base64_encode($data_json), base64_encode($ek));
        if (!isset($enc['data'])) {
            $response['error'] = true;
            $response['message'] = "Invalid ek";
            return $response;
        }
        
        $action = 'RETSAVE';
        $fields['action'] = $action;
        $fields['data'] = $enc['data']; //base64 encoded data
        
        $hmac = $this->genHashHmac256(base64_encode($data_json), $ek);
        $fields['hmac'] = $hmac;

        $GstrApiUrl = unserialize(requestUrl);
        $url = $GstrApiUrl['GSTR1_v2_url'];
        $method = 'PUT';
        $ip = $_SERVER['REMOTE_ADDR'];
        $txn = $this->getRandomCode(16);
        //send user's header
        $otherDetail['ip'] = $ip;
        $otherDetail['auth_token'] = $auth_token;
        $otherDetail['action'] = $action;
        $otherDetail['gstin'] = $gstin;
        $otherDetail['ret_period'] = $returnPeriod;
        $otherDetail['client-id'] = $ASP_client_id;
        $otherDetail['username'] = $gst_username;
        $otherDetail['state_cd'] = $state;
        $otherDetail['txn'] = $txn;
        
        $fields['other_parameters'] = $encryptedWithAppKey;
        $encodedOtherDetails = json_encode($otherDetail);
        $data = json_encode($fields);
        //send data to GST System
        
        $result = $this->sendGSPRequest($url, $data, $method, $encodedOtherDetails);
        
        if (isset($result->status_cd) && $result->status_cd == 1) {
            if (isset($result->rek)) {
                $rek = $result->rek; //temp
                //get key from rek to encrypt data in response from GST system
                $key = $this->decryptData($rek, base64_encode($ek)); //temp
                //decrypt Data from key
                $encodedData = $this->decryptData($result->data, base64_encode($key));
                if ($encodedData) {
                    $response['error'] = false;
                    $response['data'] = base64_decode($encodedData);
                    
                    $response['reqData'] = base64_encode($data_json);
                } else {
                    $response['error'] = true;
                    $response['message'] = 'Service unavailable. Please try again later';
                }
            } else {
                $response['error'] = true;
                $response['message'] = 'Rek is not set';
            }
        } else {
            if (isset($result->error->message)) {
                $msg = $result->error->message;
            } elseif (isset($result->error->desc)) {
                $msg = $result->error->desc;
            } elseif (isset($result->message)) {
                $msg = $result->message;
            } elseif (isset($result->error_msg)) {
                $msg = $result->error_msg;
            } elseif (isset($result->error->error_cd)) {
                if (isset($result->error->error_description->error_description)) {
                    $msg = $result->error->error_description->error_description;
                } elseif (isset($result->error->error_description)) {
                    $msg = $result->error->error_description;
                }
            } else {
                $msg = 'Service unavailable. Please try again later';
            }
            $response['error'] = true;
            $response['message'] = $msg;
        }
        return $response;
    }


/**
     * gstrReturnStatus method
     * Method used to get GST return status
     * @param type $json_data
     * @param type $gst_type(gstr1,gstr2,gstr3)
     * @param type $gstUserName
     * @param type $state
     * @param type $auth_token
     * @param type $sek
     * @param type $flat_app_key
     * @param type $txn
     * @param type $ip
     * @return string
     */
    public function GstrReturnStatus($json_data, $gst_type, $gst_username, $state, $auth_token, $sek,$flat_app_key,$access_token,$ASP_app_key,$ASP_client_id) {
        $ASP_client_id = $ASP_client_id;
        $ASP_app_key = $ASP_app_key;
        $other_param_data['access_token'] = $access_token;       
        $other_param_json = json_encode($other_param_data);
        //encrypt data with app-key
        $encryptedWithAppKey = $this->EncryptWithAppKey($other_param_json, $ASP_app_key);
       
        //get $ek
        $ek = $this->decryptData($sek, $flat_app_key);
        $decoded_data = json_decode($json_data, true);
        
        $gstServerResponse = false;
        $GstrApiUrl = unserialize(requestUrl);
        if ($gst_type == 'gstr1') {
            //$gstUrl = $GstrApiUrl['GSTR1_v2_url'];
            $gstUrl = $GstrApiUrl['Track_status_url'];
            if (!isset($decoded_data['ref_id'])) {
                $response['error'] = true;
                $response['message'] = "Invalid request params";
                return $response;
            }
        }else {
            $response['error'] = true;
            $response['message'] = 'Invalid GSTR Type';
            return $response;
        }
        

        $url = $gstUrl . '?action=RETSTATUS&gstin=' . $decoded_data['gstin'] . '&ret_period=' . $decoded_data['ret_period'];
        if (isset($decoded_data['ref_id'])) {
            $url .= '&ref_id=' . $decoded_data['ref_id'];
        }
        
        $url .= '&other_parameters=' . $encryptedWithAppKey;
        $ip = $_SERVER['REMOTE_ADDR'];
        $txn = $this->getRandomCode(16);
        $otherDetail['ip'] = $ip;
        $otherDetail['auth_token'] = $auth_token;
        $otherDetail['gstin'] = $decoded_data['gstin'];
        $otherDetail['action'] = 'RETSTATUS';
        $otherDetail['ret_period'] = $decoded_data['ret_period'];
        $otherDetail['client-id'] = $ASP_client_id;
        $otherDetail['username'] = strtolower($gst_username);
        $otherDetail['state_cd'] = $state;
        $otherDetail['txn'] = $txn;
        $encodedOtherDetails = json_encode($otherDetail);


        $result = $this->sendGSPRequest($url, $data = null, $method = null, $encodedOtherDetails);


        $gstServerResponse = true;
        if ($gstServerResponse == true) {
            if (isset($result->status_cd) && $result->status_cd == 1) {
                if (isset($result->rek)) {
                    $rek = $result->rek; //temp
                    //get key from rek to encrypt data in response from GST system
                    $key = $this->decryptData($rek, base64_encode($ek)); //temp
                    //decrypt Data from key
                    $encodedData = $this->decryptData($result->data, base64_encode($key));

                    if ($encodedData) {
                        $response['error'] = false;
                        $response['data'] = base64_decode($encodedData);
                    } else {
                        $response['error'] = true;
                        $response['message'] = 'Service unavailable. Please try again later';
                    }
                } else {
                    $response['error'] = true;
                    $response['message'] = 'Rek is not set';
                }
            } else {
                if (isset($result->error->message)) {
                    $msg = $result->error->message;
                } elseif (isset($result->error->desc)) {
                    $msg = $result->error->desc;
                } elseif (isset($result->message)) {
                    $msg = $result->message;
                } elseif (isset($result->error_msg)) {
                    $msg = $result->error_msg;
                } elseif (isset($result->error->error_cd)) {
                    if (isset($result->error->error_description->error_description)) {
                        $msg = $result->error->error_description->error_description;
                    } elseif (isset($result->error->error_description)) {
                        $msg = $result->error->error_description;
                    }
                } else {
                    $msg = 'Service unavailable. Please try again later';
                }
                $response['error'] = true;
                $response['message'] = $msg;
            }
        } else {
            $response['error'] = true;
            $response['message'] = 'Service unavailable. Please try again later';
        }

        return $response;
    }


/**GetGSTRData Method
     */

public function getGstrData($json_encoded_data, $gst_type, $gstUserName, $state, $auth_token, $sek, $flat_app_key,$access_token,$ASP_app_key,$ASP_client_id) {
        //check GSP token expire
        
        $ASP_client_id = $ASP_client_id;
        $ASP_app_key = $ASP_app_key;
        $other_param_data['access_token'] = $access_token;
        
        $other_param_json = json_encode($other_param_data);

        //encrypt data with app-key
        $encryptedWithAppKey = $this->EncryptWithAppKey($other_param_json, $ASP_app_key);
        //decode JSON input data
        $decoded_data = json_decode($json_encoded_data, true);

        $GstrApiUrl = unserialize(requestUrl);
        $ip = $_SERVER['REMOTE_ADDR'];
        $txn = $this->getRandomCode(16);
        $ek = $this->decryptData($sek, $flat_app_key);

        $response['error'] = false;
         if ($gst_type == 'gstr2a') { //for GSTR2A
            if ($decoded_data['action'] == 'B2B' || $decoded_data['action'] == 'B2BA' || $decoded_data['action'] == 'CDN' || $decoded_data['action'] == 'CDNA' || $decoded_data['action'] == 'TDS' || $decoded_data['action'] == 'TDSA' || $decoded_data['action'] == 'TCS' || $decoded_data['action'] == 'ISD' || $decoded_data['action'] == 'ISDA' || $decoded_data['action'] == 'IMPG' || $decoded_data['action'] == 'IMPGSEZ') {
                if (!isset($decoded_data['gstin']) || !isset($decoded_data['ret_period'])) {
                    $response['error'] = true;
                    $response['message'] = "Invalid request params";
                    return $response;
                }
            } else {
                $response['error'] = true;
                $response['message'] = "Invalid action";
                return $response;
            }
            if($decoded_data['action'] == 'TDS' || $decoded_data['action'] == 'TDSA'){
                $GstrApiUrl['GSTR2A_v2_url'] = str_replace('v0.3','v1.0', $GstrApiUrl['GSTR2A_v2_url']);
            }
            $url = $GstrApiUrl['GSTR2A_v2_url'] . '?action=' . $decoded_data['action'] . '&gstin=' . $decoded_data['gstin'] . '&ret_period=' . $decoded_data['ret_period'];
            if (isset($decoded_data['ctin'])) {
                $url .= '&ctin=' . $decoded_data['ctin'];
            }
            if (isset($decoded_data['from_time'])) {
                $url .= '&from_time=' . $decoded_data['from_time'];
            }
            
        } elseif ($gst_type == 'gstr1') {//for GSTR1
            if ($decoded_data['action'] == 'B2B' || $decoded_data['action'] == 'B2BA' || $decoded_data['action'] == 'B2CL' || $decoded_data['action'] == 'B2CLA' || $decoded_data['action'] == 'B2CS' || $decoded_data['action'] == 'B2CSA' || $decoded_data['action'] == 'CDNR' || $decoded_data['action'] == 'CDNRA' || $decoded_data['action'] == 'CDNUR' || $decoded_data['action'] == 'CDNURA' || $decoded_data['action'] == 'NIL' || $decoded_data['action'] == 'EXP' || $decoded_data['action'] == 'EXPA' || $decoded_data['action'] == 'AT' || $decoded_data['action'] == 'ATA' || $decoded_data['action'] == 'HSNSUM' || $decoded_data['action'] =='DOCISS') {
                if (!isset($decoded_data['gstin']) || !isset($decoded_data['ret_period'])) {
                    $response['error'] = true;
                    $response['message'] = "Invalid request params";
                    return $response;
                }
            }
            $url = $GstrApiUrl['GSTR1_v2_url'] . '?action=' . $decoded_data['action'] . '&gstin=' . $decoded_data['gstin'] . '&ret_period=' . $decoded_data['ret_period'];
            if ($decoded_data['action'] == 'B2B' || $decoded_data['action'] == 'B2BA' || $decoded_data['action'] == 'B2CL' || $decoded_data['action'] == 'B2CLA' || $decoded_data['action'] == 'B2CS' || $decoded_data['action'] == 'B2CSA' || $decoded_data['action'] == 'CDNR' || $decoded_data['action'] == 'CDNRA' || $decoded_data['action'] == 'CDNUR' || $decoded_data['action'] == 'CDNURA' || $decoded_data['action'] == 'NIL' || $decoded_data['action'] == 'EXP' || $decoded_data['action'] == 'EXPA' || $decoded_data['action'] == 'AT' || $decoded_data['action'] == 'ATA' || $decoded_data['action'] == 'TXP' || $decoded_data['action'] == 'ECOM' || $decoded_data['action'] == 'HSNSUM' || $decoded_data['action'] =='DOCISS') {

                if (isset($decoded_data['action_required'])) {
                    $url .= '&action_required=' . $decoded_data['action_required'];
                }
                if (isset($decoded_data['state_cd'])) {
                    $url .= '&state_cd=' . $decoded_data['state_cd'];
                }
                if (isset($decoded_data['ctin'])) {
                    $url .= '&ctin=' . $decoded_data['ctin'];
                }
                if (isset($decoded_data['from_time'])) {
                    $url .= '&from_time=' . $decoded_data['from_time'];
                }
                

            } else {
                $response['error'] = true;
                $response['message'] = 'Invalid action.';
            }
        }  else {
            $response['error'] = true;
            $response['message'] = 'Invalid invoice request.';
        }
        $url .= '&other_parameters=' . $encryptedWithAppKey;
        if ($response['error'] == false) {
            $otherDetail['ip'] = $ip;
            $otherDetail['auth_token'] = $auth_token;
            $otherDetail['action'] = $decoded_data['action'];
            $otherDetail['gstin'] = $decoded_data['gstin'];
            $otherDetail['ret_period'] = $decoded_data['ret_period'];
            $otherDetail['client-id'] = $ASP_client_id;
            $otherDetail['username'] = strtolower($gstUserName);
            $otherDetail['state_cd'] = $state;
            $otherDetail['txn'] = $txn;            
            $encodedOtherDetails = json_encode($otherDetail);
            $result = $this->sendGSPRequest($url, $data = null, $method = null, $encodedOtherDetails);
            

            // die();
            if (isset($result->status_cd) && ($result->status_cd == 1 || $result->status_cd == 2 || $result->status_cd == 3)) {
                if (isset($result->rek)) {
                    $rek = $result->rek; //temp
                    //get key from rek to encrypt data in response from GST system
                    $key = $this->decryptData($rek, base64_encode($ek)); //temp
                    //decrypt Data from key
                    $encodedData = $this->decryptData($result->data, base64_encode($key));
                    if ($encodedData) {
                        $response['error'] = false;
                        $response['data'] = base64_decode($encodedData);
                    } else {
                        $response['error'] = true;
                        $response['message'] = 'Response data is not getting decrypt';
                    }
                } else {
                    $response['error'] = true;
                    $response['message'] = 'Rek is not set';
                }
            } else {
                if (isset($result->error->message)) {
                    $msg = $result->error->message;
                } elseif (isset($result->error->desc)) {
                    $msg = $result->error->desc;
                } elseif (isset($result->message)) {
                    $msg = $result->message;
                } elseif (isset($result->error_msg)) {
                    $msg = $result->error_msg;
                } elseif (isset($result->error->error_cd)) {
                    if (isset($result->error->error_description->error_description)) {
                        $msg = $result->error->error_description->error_description;
                    } elseif (isset($result->error->error_description)) {
                        $msg = $result->error->error_description;
                    }
                } else {
                    $msg = 'Service unavailable. Please try again later';
                }
                $response['error'] = true;
                $response['message'] = $msg;
            }
        }
        return $response;
    }


    /**
     * send request
     */
    function sendGSPRequest($url, $data = null, $method = null, $other_detail_json = null) {
        $HeaderOption = array('Content-Type: application/json');
        if ($other_detail_json != null) {
            $other_detail = json_decode($other_detail_json, true);
            foreach ($other_detail as $key => $value) {
                array_push($HeaderOption, $key . ':' . $value);
            }
        }
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $url);
        //curl_setopt($ch, CURLOPT_HTTPHEADER, array('Content-Type: application/json', 'auth-token: 8a227e0ba56042a0acdf98b3477d2c03', 'clientid: l7xx6df7496552824f15b7f4523c0a1fc114', 'client-secret: f328fe52752349c893aa93adcffed8f5', 'state-cd: 11', 'username: GSPTESTUSERMICRATest', 'ip-usr: 12.8.91.80', 'txn: returns'));
        curl_setopt($ch, CURLOPT_HTTPHEADER, $HeaderOption);
        if ($method == 'POST' || $method == 'PUT') {
            if ($method == 'PUT') {
                curl_setopt($ch, CURLOPT_CUSTOMREQUEST, "PUT");
            } else {
                curl_setopt($ch, CURLOPT_POST, 1);
            }
            curl_setopt($ch, CURLOPT_POSTFIELDS, $data);
        }
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_VERBOSE, true);
        curl_setopt($ch, CURLOPT_STDERR, fopen('php://stderr', 'w'));
        // Execute post
        $result = curl_exec($ch);
        $status_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $curl_err = curl_error($ch);
        curl_close($ch);
        $result2 = json_decode($result);


        /* if (isset($result2->status_cd) && $result2->status_cd == 0) {
          return $result2;
      } */

      return $result2;
  }

}
