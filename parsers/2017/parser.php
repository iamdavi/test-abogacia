<?php

include_once(__DIR__ . '\..\classes\TestFile.php');

/**
 * @link https://www.mjusticia.gob.es/es/Ciudadano/EmpleoPublico/Documents/Plantilla%20Definitiva%20-%20CASTELLANO.pdf
 * @link https://www.mjusticia.gob.es/es/Ciudadano/EmpleoPublico/Documents/PLANTILLA%20CASTELLANO.pdf
 * @param array Needed data of each file
 */
$files_data = [
	[
		'name' => __DIR__ . '\..\..\resources\2017\txt\primera_convocatoria\text_modelo_a.txt',
		'output' => __DIR__ . '\..\..\resources\2017\json\primera_convocatoria\2017_modelo_a.json',
		'answers' => [
			'10322100221200302020203330231310132132311322020330330121',
			'20110230301231231232001230',
			'211132100112123203020333222',
			'20021323203332103300102012',
			'230321121302001310023012001',
		],
	],
	[
		'name' => __DIR__ . '\..\..\resources\2017\txt\primera_convocatoria\text_modelo_b.txt',
		'output' => __DIR__ . '\..\..\resources\2017\json\primera_convocatoria\2017_modelo_b.json',
		'answers' => [
			'03302022311323121310313023303202020300213300011223303121',
			'10023213213210103201102203',
			'233302030232121100123111222',
			'02001033012333023213200221',
			'01230200131000221112033201',
		],
	],
	[
		'name' => __DIR__ . '\..\..\resources\2017\txt\segunda_convocatoria\text.txt',
		'output' => __DIR__ . '\..\..\resources\2017\json\segunda_convocatoria\2017.json',
		'answers' => [
			'20223200330013223122102122121332200131102033203201011103',
			'30011210231201323002232020',
			'313002310231013012110021220',
			'131113020033133130012202210',
			'211012312212302123310321200',
		],
	],
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
