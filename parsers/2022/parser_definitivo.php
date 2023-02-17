<?php

include_once(__DIR__ . '\..\classes\TestFile.php');

/**
 * @link https://www.mjusticia.gob.es/es/Ciudadano/EmpleoPublico/Documents/PLANTILLA%20DEFINITIVA%20-%20CASTELLANO%202022.1.pdf
 * @param string Path of the content file
 */
$file_name = __DIR__ . '\..\..\resources\2022\txt\text_definitivo.txt';
$output_file_name = __DIR__ . '\..\..\resources\2022\json\2022_definitivo.json';

$correct_answers = [
	'13110202210212210033102112001321222203121302120232',
	'32203311003001123233113',
	'1031231020132320101010321',
	'1122023220111120011010013',
	'2113001230313001231130310',
];

$file_parser = new TestFile($file_name, $correct_answers);
$file_parser->parseFile();
$json_string = $file_parser->getArrayFileContent();

if (file_exists($output_file_name)) {
	unlink($output_file_name);
}
file_put_contents($output_file_name, $json_string);

echo "File generated successfully in: $output_file_name";
