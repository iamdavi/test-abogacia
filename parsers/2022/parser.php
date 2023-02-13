<?php

$handle = fopen("..\\resources\\2022\\text.txt", "r");

$json_data = [];
$current_section = 'comunes';
$current_sub_section = 'preguntas';
$question_index = 0;

while (($line = fgets($handle)) !== false) {
	$line_arr = explode($line, ' ');
	if (count($line_arr) == 1 && is_numeric($line_arr[0])) {
		// Skip number of page
		continue;
	}
	if (is_numeric($line_arr[0]) && $line_arr[1] == '-') {
		// Insert question
		$question_number = (int) array_shift($line_arr);
		unset($line_arr[0]); // remove the '-'
		$question_index = $question_number > $question_index
			? $question_number
			: $question_index + 1;
		$json_data[$current_section][$question_index] = implode(' ', $line_arr);
	}
}

fclose($handle);
