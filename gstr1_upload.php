<?php
error_reporting(E_ALL);
include_once './libs/common.php';

//accessToken();
//getOtp();
//verifyOtp();
//uploadData();
//getReturnStatus();
GetData();
//logout();

function accessToken()
{
	$common = new common();
	$resp = $common->getAccessToken();

	echo "<br><br><strong>Response</strong><br><br>";
	echo '<pre>';
	print_r($resp);
}


function getOtp()
{
	$aspUserInfo = unserialize(accessTokenInfo);
	$GstinInfo = unserialize(GstinInfo);
	$common = new common();
	//get Authentication from Masters India
	$responseAccessToken = $common->getAccessToken();
	//print_r($GstinInfo);die;
	$gstin=$GstinInfo['gstin'];//Eway GSTIN
	$gst_username=$GstinInfo['gst_username'];
	$state=$GstinInfo['state'];
	$access_token=$responseAccessToken['access_token'];//Access_token from Masters India
	$ASP_app_key=$responseAccessToken['app_key'];//App key from Masters India
	$ASP_client_id=$aspUserInfo['client_id'];//Shared Client Id 

	//OTP Request
	$response_otp = $common->OTPRequest($gst_username,$state,$access_token,$ASP_client_id,$ASP_app_key,$gstin);
	echo "<br><br><strong>Response</strong><br><br>";
	print_r($response_otp);die;
}



function verifyOtp()
{
	$aspUserInfo = unserialize(accessTokenInfo);
	$GstinInfo = unserialize(GstinInfo);
	$common = new common();
	//get Authentication from Masters India
	$responseAccessToken = $common->getAccessToken();

	$otp = "221100";//OTP sent on registered mobile number
	$gstin=$GstinInfo['gstin'];
	$gst_username=$GstinInfo['gst_username'];
	$state=$GstinInfo['state'];
	$access_token=$responseAccessToken['access_token'];//Access_token from Masters India
	$ASP_app_key=$responseAccessToken['app_key'];//App key from Masters India
	$ASP_client_id=$aspUserInfo['client_id'];//Shared Client Id 

	//$encryptedAppKey=$response_otp['encrypt_app_key'];// which is used at the time of OTP request
	//$flatAppKey = $response_otp['flat_app_key'];// which is used at the time of OTP request
	$encryptedAppKey="Zjw/XcfasHqgll/XdjRI/7nAWxVFFzqy2nwEDNW7xACw0BlBgehI0Jp99BnmsPtZGJsj1REjD3lbpR+Zop0ao4N4XtE5Amqmxi8QjTD/jHEb51EsXv4q7pYjLoQP7qTPUlNp0DlITLyz/J05Qc0K30hiKKfHJQqWKcuPCSFFAfJRSmcN9QhOKcT61K9Ohrj/WOyORn1ySieCtH8bHK/sps6EyCuo6oP9cmAz3tFwbLjDIxPidXQpm9Ce7b3CICGjp9GouxJdog1vJS5YWLOUm7cMoDa4T75mYVdb54EzPm4lHWOCoIBkYp+w0/M0j1C25yVkLRN4qikSiFm54YtxzA==";
	$flatAppKey ="MTJJUE83WmZzdzFCQkt0dnlyUmhlTEpuWHZuYjh4WTI=";
	// authenticate from GST
	
	$response_authtoken = $common->authtoken($gst_username,$state,$access_token,$ASP_client_id,$ASP_app_key,$gstin,$otp,$encryptedAppKey,$flatAppKey);
	echo "<br><br><strong>Response</strong><br><br>";
	print_r($response_authtoken);die;
}




function uploadData()
{
	$aspUserInfo = unserialize(accessTokenInfo);
	$GstinInfo = unserialize(GstinInfo);
	$common = new common();
	//get Authentication from Masters India
	$responseAccessToken = $common->getAccessToken();
	$data_json = '{"gstin":"33GSPTN9511G3Z3","fp":"072021","gt":50000000,"cur_gt":0,"b2b":[{"ctin":"05AAAPG7885R002","inv":[{"inv_typ":"R","rchrg":"N","inum":"F20081","idt":"12-07-2021","pos":"05","val":725277.24,"itms":[{"itm_det":{"iamt":110386.56,"txval":613258.68,"rt":18,"csamt":0},"num":1}]}]}]}';

	$gstrType = 'gstr1';
	$returnPeriod = '072021';
	$gstin=$GstinInfo['gstin'];
	$gst_username=$GstinInfo['gst_username'];
	$state=$GstinInfo['state'];	

	$access_token=$responseAccessToken['access_token'];//Access_token from Masters India
	$ASP_app_key=$responseAccessToken['app_key'];//App key from Masters India
	$ASP_client_id=$aspUserInfo['client_id'];//Shared  masters indaiClient Id 

	//$encryptedAppKey=$response_otp['encrypt_app_key'];// which is used at the time of OTP request
	//$flatAppKey = $response_otp['flat_app_key'];// which is used at the time of OTP request
	$encryptedAppKey="Zjw/XcfasHqgll/XdjRI/7nAWxVFFzqy2nwEDNW7xACw0BlBgehI0Jp99BnmsPtZGJsj1REjD3lbpR+Zop0ao4N4XtE5Amqmxi8QjTD/jHEb51EsXv4q7pYjLoQP7qTPUlNp0DlITLyz/J05Qc0K30hiKKfHJQqWKcuPCSFFAfJRSmcN9QhOKcT61K9Ohrj/WOyORn1ySieCtH8bHK/sps6EyCuo6oP9cmAz3tFwbLjDIxPidXQpm9Ce7b3CICGjp9GouxJdog1vJS5YWLOUm7cMoDa4T75mYVdb54EzPm4lHWOCoIBkYp+w0/M0j1C25yVkLRN4qikSiFm54YtxzA=="; // which is used at the time of OTP request
	$flatAppKey ="MTJJUE83WmZzdzFCQkt0dnlyUmhlTEpuWHZuYjh4WTI=";//which is used at the time of OTP request
	$sek = 'Mxdgg+S6f6jHXAh+vFYYtpfrDV+8Cr3Qww/7HFV+AKYOJpht+nGkUN1LlVUZRoGw';//Received with auth token
	$auth_token = '5f443d9cf86c4f98bfa0548453f3c5df';//Which is received in authentication API from GST
	
	
	$response= $common->saveGSTRData($gst_username,$state,$access_token,$ASP_client_id,$ASP_app_key,$gstin,$sek,$encryptedAppKey,$flatAppKey,$data_json,
	$gstrType,$returnPeriod,$auth_token);
	echo "<br><br><strong>Response</strong><br><br>";
	print_r($response);die;
}

function getReturnStatus(){
	$aspUserInfo = unserialize(accessTokenInfo);
	$GstinInfo = unserialize(GstinInfo);
	$common = new common();
	//get Authentication from Masters India
	$responseAccessToken = $common->getAccessToken();
	
	$gstrType = 'gstr1';
	$returnPeriod = '072021';
	$gstin=$GstinInfo['gstin'];
	$gst_username=$GstinInfo['gst_username'];
	$state=$GstinInfo['state'];	

	$access_token=$responseAccessToken['access_token'];//Access_token from Masters India
	$ASP_app_key=$responseAccessToken['app_key'];//App key from Masters India
	$ASP_client_id=$aspUserInfo['client_id'];//Shared  masters indaiClient Id 

	
	//$flatAppKey = $response_otp['flat_app_key'];// which is used at the time of OTP request	
	$flatAppKey ="MTJJUE83WmZzdzFCQkt0dnlyUmhlTEpuWHZuYjh4WTI=";//which is used at the time of OTP request
	$sek = 'Mxdgg+S6f6jHXAh+vFYYtpfrDV+8Cr3Qww/7HFV+AKYOJpht+nGkUN1LlVUZRoGw';//Received with auth token
	$auth_token = '5f443d9cf86c4f98bfa0548453f3c5df';//Which is received in authentication API from GST

	$fields['gstin'] = $gstin;
  $fields['ret_period'] = $returnPeriod;
  //for gstr1
  $fields['ref_id'] = 'b2cdefcd-2286-408a-9287-41517dee888d';
  
  $json_encoded_data = json_encode($fields);
	
	$response= $common->GstrReturnStatus($json_encoded_data, $gstrType, $gst_username, $state, $auth_token, $sek, $flatAppKey,$access_token,$ASP_app_key,$ASP_client_id);
	echo "<br><br><strong>Response</strong><br><br>";
	print_r($response);die;




}


 function GetData(){
   $aspUserInfo = unserialize(accessTokenInfo);
	$GstinInfo = unserialize(GstinInfo);
	$common = new common();
	//get Authentication from Masters India
	$responseAccessToken = $common->getAccessToken();
	$access_token=$responseAccessToken['access_token'];//Access_token from Masters India
	
	$ASP_app_key=$responseAccessToken['app_key'];//App key from Masters India
	
	$ASP_client_id=$aspUserInfo['client_id'];//Shared Client Id 

    $fields['gstin']      = $GstinInfo['gstin'];
    $fields['fy']         = "2019-20";
    $fields['ret_period'] = "082019";
    $fields['action']     = 'B2B';
    $json_encoded_data    = json_encode($fields);
    $gst_type             = 'gstr1';
    $gstUserName          = $GstinInfo['gst_username'];
    $state                = $GstinInfo['state'];

    $auth_token           = '5f443d9cf86c4f98bfa0548453f3c5df';

	$flatAppKey ="MTJJUE83WmZzdzFCQkt0dnlyUmhlTEpuWHZuYjh4WTI=";//which is used at the time of OTP request
	$sek = 'Mxdgg+S6f6jHXAh+vFYYtpfrDV+8Cr3Qww/7HFV+AKYOJpht+nGkUN1LlVUZRoGw';//Received with auth token

    $Response   = $common->getGstrData($json_encoded_data,$gst_type,$gstUserName,$state,$auth_token,$sek,$flatAppKey,$access_token,$ASP_app_key,$ASP_client_id);

    echo "<br>Response: <br>";
    //$Response = json_decode($Response['data'],true);
    print_r($Response);
    die();
}



function logout()
{
	$aspUserInfo = unserialize(accessTokenInfo);
	$GstinInfo = unserialize(GstinInfo);
	$common = new common();
	//get Authentication from Masters India
	$responseAccessToken = $common->getAccessToken();

	//$otp = "709739";//OTP sent on registered mobile number
	$gstin=$GstinInfo['gstin'];
	$gst_username=$GstinInfo['gst_username'];
	$state=$GstinInfo['state'];
	$access_token=$responseAccessToken['access_token'];//Access_token from Masters India
	$ASP_app_key=$responseAccessToken['app_key'];//App key from Masters India
	$ASP_client_id=$aspUserInfo['client_id'];//Shared Client Id 

	//$auth_token = $response_authtoken['auth_token'];
	
	//$encryptedAppKey=$response_otp['encrypt_app_key'];// which is used at the time of OTP request
	

	$auth_token = "88a8fc02b10442ae81723c95e71db438";
	$encryptedAppKey="zURxtJtzjbe11vgn+k+E9/qYV9HYAW0N8M2T/9xWP5mBWwiBSGIIiOyVzENcOMXVpaTjtLMcfW1AdZzwstE/o9UwCl4/ecb6GCQkP76nNfy1Pcdpaje7QsClKQCpfY8+9lpDGbAij0GlWSXGwZY1QErbAoFb+oBnhKSEwhPh/X6532k7TCY1UbOtfUK7ne/Mv6hqyy0gwr6Vr1M2TkUgzTdf9PoAOS9B1bAmUUltaxXI3rmQoGPTYfqOFeKX5GRj26sjXeccYxRK4irDxtSjSsi8bYltwtM/KX0HfyRJuID+rOa8E3KC6mLKvQZ+2Kcvgv1Q/seUF199xcRtXAVvdg==";
	
	$response = $common->gstLogout($gst_username,$state,$access_token,$ASP_client_id,$ASP_app_key,$gstin,$auth_token,$encryptedAppKey);
	echo "<br><br><strong>Response</strong><br><br>";
	print_r($response);die;
}

?>