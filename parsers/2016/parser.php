<?php

include_once(__DIR__ . '\..\classes\TestFile.php');

/**
 * @link https://www.mjusticia.gob.es/es/Ciudadano/EmpleoPublico/Documents/1292428106587-Examen_abogac%C3%ADa_29oct2016._Castellano.pdf
 * @param string Path of the content file
 */
$file_name = __DIR__ . '\..\..\resources\2016\txt\text.txt';
$output_file_name = __DIR__ . '\..\..\resources\2016\json\2016.json';

$correct_answers = [
	'0311233023201200201032101010100131332202012000131123322',
	'110203331231310301200212',
	'210023233301020030132213032',
	'103133110112211302130120210',
	'12022120021201230011011020',
];

$file_parser = new TestFile($file_name, $correct_answers);
$file_parser->parseFile();
$json_string = $file_parser->getArrayFileContent();

if (file_exists($output_file_name)) {
	unlink($output_file_name);
}
file_put_contents($output_file_name, $json_string);

echo "File generated successfully in: $output_file_name";
