<?php

include_once(__DIR__ . '\.\classes\TestFile.php');

/**
 * @link https://www.mjusticia.gob.es/es/Ciudadano/EmpleoPublico/Documents/PLANTILLA%20PROVISIONAL%202022.1%20-%20CASTELLANO.pdf
 * @param string Path of the content file
 */
$file_name = __DIR__ . '\..\resources\2022\txt\text.txt';
$output_file_name = __DIR__ . '\..\resources\2022\json\2022.json';

$file_parser = new TestFile($file_name);
$file_parser->parseFile();

$json_string = $file_parser->getArrayFileContent();

if (file_exists($output_file_name)) {
	unlink($output_file_name);
}
file_put_contents($output_file_name, $json_string);

echo "File generated successfully in: $output_file_name";
