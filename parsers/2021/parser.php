<?php

/**
 * @link https://www.mjusticia.gob.es/es/Ciudadano/EmpleoPublico/Documents/Plantilla%20Definitiva%20-%20CASTELLANO.pdf
 * @link https://www.mjusticia.gob.es/es/Ciudadano/EmpleoPublico/Documents/PLANTILLA%20CASTELLANO.pdf
 * @param array Needed data of each file
 */
$files_data = [
	[
		'name' => __DIR__ . '\..\..\resources\2021\txt\text_definitivo.txt',
		'output' => __DIR__ . '\..\..\resources\2021\json\2021_definitivo.json',
		'answers' => [],
	],
	[
		'name' => __DIR__ . '\..\..\resources\2021\txt\text_provisional.txt',
		'output' => __DIR__ . '\..\..\resources\2021\json\2021_provisional.json',
		'answers' => [],
	]
];

foreach ($files_data as $file_data) {
	$file_name = $file_data['name'];
	$output_file_name = $file_data['name'];
	$correct_answers = $file_data['answer'];

	$file_parser = new TestFile($file_name, $correct_answers);
	$file_parser->parseFile();
	$json_string = $file_parser->getArrayFileContent();

	if (file_exists($output_file_name)) {
		unlink($output_file_name);
	}
	file_put_contents($output_file_name, $json_string);

	echo "File generated successfully in: $output_file_name \n";
}
