<?php

include_once(__DIR__ . '\..\classes\TestFile.php');

/**
 * @link https://www.mjusticia.gob.es/es/Ciudadano/EmpleoPublico/Documents/Plantilla%20Definitiva%20-%20CASTELLANO.pdf
 * @link https://www.mjusticia.gob.es/es/Ciudadano/EmpleoPublico/Documents/PLANTILLA%20CASTELLANO.pdf
 * @param array Needed data of each file
 */
$files_data = [
	[
		'name' => __DIR__ . '\..\..\resources\2021\txt\text_definitivo.txt',
		'output' => __DIR__ . '\..\..\resources\2021\json\2021_definitivo.json',
		'answers' => [
			'22111320232130120320022321331211312211003310130223',
			'13211211003232013313221',
			'0113210310030120121212022',
			'2303221121303131320101333',
			'2221120120330110211010223',
		],
	],
	[
		'name' => __DIR__ . '\..\..\resources\2021\txt\text_provisional.txt',
		'output' => __DIR__ . '\..\..\resources\2021\json\2021_provisional.json',
		'answers' => [
			'22111320232130120320022121331211312211003310130223202201',
			'132112110032320133132210221001312',
			'011321031100301201212120220',
			'230322112130313132010133133',
			'222112012033011021101022323',
		],
	]
];

foreach ($files_data as $file_data) {
	$file_name = $file_data['name'];
	$output_file_name = $file_data['output'];
	$correct_answers = $file_data['answers'];

	$file_parser = new TestFile($file_name, $correct_answers);
	$file_parser->parseFile();
	$json_string = $file_parser->getArrayFileContent();

	if (file_exists($output_file_name)) {
		unlink($output_file_name);
	}
	file_put_contents($output_file_name, $json_string);

	echo "\n\nFile generated successfully in: $output_file_name \n\n";
}
