<?php

$host = "https://api.mastersindia.co";
$requestUrl=array(
    'access_token'=>$host.'/oauth/access_token',
    'auth_url' => $host . '/v0.2/authenticate',
    'GSTR1_v2_url' => $host . '/v2.0/returns/gstr1',
    'GSTR2A_v2_url' => $host . '/v2.0/returns/gstr2a',
    'Track_status_url' => $host . '/v0.3/returns',
    'host'=>$host 
);
define ("requestUrl", serialize ($requestUrl));

//Sample user data information to get access_token
$accessTokenInfo=array(    
    'username' =>'apiiso@mastersindia.co',
    'password' =>'Eway@123#',
    'client_id' =>'2HkHiaXfPdNRTNwxaCASbplGNpiJSLkB',
    'client_secret' =>'I0FJ6lHO7pjTLqpcbwzyaORKJr5kht38',
    'grant_type' =>'password',
);
define ("accessTokenInfo", serialize ($accessTokenInfo));


// GSTIN information 
$GstinInfo=array(      
    'gstin' =>'33GSPTN9511G3Z3',
    'state' =>'33',
    'gst_username' =>'TECCENT.TN.TP.1',
    
);
define ("GstinInfo", serialize ($GstinInfo));




?>




