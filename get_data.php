<?php
//address of the server where db is installed
$servername = "localhost";
//username to connect to the db
//the default value is root
$username = "netflow";
//password to connect to the db
//this is the value you specified during installation of WAMP stack
$password = "admin1234";
//name of the db under which the table is created
$dbName = "netflowdb";
//establishing the connection to the db.
$conn = new mysqli($servername, $username, $password, $dbName);
//checking if there were any error during the last connection attempt
if ($conn->connect_error) {
  die("Connection failed: " . $conn->connect_error);
}
//echo "Connected successfully<br>";

// collect value of input field
$datefrom = $_REQUEST['datefrom'];
$dateto = $_REQUEST['dateto'];
$inputfield = $_REQUEST['inputfield'];

//run select query with "other".
// source: http://stackoverflow.com/questions/1524403/sql-to-produce-top-10-and-other
$sql = "SELECT $inputfield, sum(IN_BYTES) IN_BYTES
		FROM (SELECT COALESCE(T2.$inputfield, 'OTHER') $inputfield, T1.IN_BYTES
				FROM (SELECT $inputfield, sum(IN_BYTES) IN_BYTES
						FROM flows where TIMESTAMP >= '$datefrom' and TIMESTAMP <= '$dateto'
					  GROUP BY $inputfield ORDER BY sum(IN_BYTES) ) T1
					LEFT JOIN 
					 (SELECT $inputfield, sum(IN_BYTES) IN_BYTES
						FROM flows where TIMESTAMP >= '$datefrom' and TIMESTAMP <= '$dateto'
					  GROUP BY $inputfield ORDER BY sum(IN_BYTES) DESC LIMIT 10) T2 
					on T1.$inputfield = T2.$inputfield) T
		GROUP BY $inputfield ORDER BY sum(IN_BYTES) DESC";

$result = $conn->query($sql);

//initialize the array to store the processed data
$jsonArray = array();
//check if there is any data returned by the SQL Query
if ($result->num_rows > 0) {
  //Converting the results into an associative array
  while($row = $result->fetch_assoc()) {
	$jsonArrayItem = array();
	if ($row[$inputfield] == 'OTHER') {
		$jsonArrayItem['label'] = $row[$inputfield];
	} elseif ($inputfield == 'IPV4_SRC_ADDR' || $inputfield == 'IPV4_DST_ADDR') {
		$jsonArrayItem['label'] = hexdec(substr($row[$inputfield], 0, 2)).".".hexdec(substr($row[$inputfield], 2, 2)).".".hexdec(substr($row[$inputfield], 4, 2)).".".hexdec(substr($row[$inputfield], 6, 2));
	} elseif ($inputfield == 'L4_DST_PORT' ) {
		$jsonArrayItem['label'] = hexdec($row[$inputfield]);
	} elseif ($inputfield == 'APPID' ) {
		$jsonArrayItem['label'] = $row[$inputfield];
	}
	$jsonArrayItem['value'] = $row['IN_BYTES'];
	//append the above created object into the main array.
	array_push($jsonArray, $jsonArrayItem);
  }
}

//close the connection to the db.
$conn->close();

//set the response content type as JSON
header('Content-type: application/json');
//output the return value of json encode using the echo function. 
echo json_encode($jsonArray);
?>
