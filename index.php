<?php
$url="http://127.0.0.1:8000/";
$headers = array("Content-Type:multipart/form-data");
$curl = curl_init();
curl_setopt_array(
    $curl, array(
        CURLOPT_URL => $url,
        CURLOPT_HEADER => true,
        CURLOPT_HTTPHEADER => $headers,
        CURLOPT_POST=> true,
        CURLOPT_POSTFIELDS => $data,
        CURLOPT_RETURNTRANSFER => true,
    )
);

$response = curl_exec($curl);

$res = [
    "res" => $response
 ];


?>
<html>
    <head>
    </head>
    <body>
        reult: 
        <?php $err = curl_error($curl);
            if ($err) {
            echo 'cURL Error #:' . $err;
            } else {
            echo json_encode($res);
            } 
        ?>
    </body>
</html>