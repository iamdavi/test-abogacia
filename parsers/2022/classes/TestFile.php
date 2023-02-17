<?php

include_once(__DIR__ . '\.\TestSection.php');
include_once(__DIR__ . '\.\TestQuestion.php');

class TestFile
{
	private $file_name;
	private $test_sections;
	private $last_type_created = '';
	private $possible_answer_letters = ['a', 'b', 'c', 'd', 'e', 'f'];
	private $correct_answers_by_section = [
		'13110202210212210033102112001321020222031231302120232101',
		'32203311003001112323311311',
		'103123102013232010101032132',
		'112202322011112001101001303',
		'211300122303130012311303103',
	];

	public function __construct(string $file_name = '')
	{
		$this->file_name = $file_name;
		$this->test_sections = [];
	}

	/**
	 * Method to parse the file.
	 * 
	 * @throws Exception 	In case the file doesn't exist.
	 * 
	 * @return void
	 */
	public function parseFile()
	{
		$file_name = $this->getFileName();
		if (!file_exists($file_name)) {
			throw new Exception("¡El archivo $file_name no existe!", 1);
			die();
		}

		$handle = fopen($file_name, "r");
		while (($line = fgets($handle)) !== false) {
			$this->parseLine($line);
		}
		fclose($handle);
	}

	/**
	 * Method that parse line content of file.
	 * 
	 * @param 	string 	$file_line 		Content of file line
	 * 
	 * @return 	void
	 */
	public function parseLine(string $file_line)
	{
		$line = str_replace(array("\r", "\n"), '', $file_line);

		if (
			is_numeric($line)
			|| $line == 'Preguntas de reserva'
			|| $line == 'A. MATERIAS ESPECÍFICAS'
			|| $line == 'Preguntas sobre derechos civiles forales'
		) { // Skip dummy lines
			return;
		}

		if ($section_title = $this->isNewSection($line)) { // New section
			$this->createTestSection($section_title);
			$this->setLastTypeCreated('section');
			return;
		}

		$line_arr = explode(' ', $line, 3);

		if ($this->isNewQuestion($line_arr)) { // New question
			$this->setLastTypeCreated('question');
			return;
		}

		if ($this->isNewAnswer($line_arr)) {
			$this->setLastTypeCreated('answer');
			return;
		}

		$last_type = $this->getLastTypeCreated();

		$test_question = $this->getTestSection()->getTestQuestion();
		if ($last_type == 'question') {
			$test_question->appendQuestionString(' ' . $line);
		} elseif ($last_type == 'answer') {
			$test_question->appendAnswerString(' ' . $line);
		}
	}

	/**
	 * Method that check if the line_arr passed has the format of an answer,
	 * if so, add to the las TestQuestion the beggining of the answer and 
	 * return true, if not, only returns false.
	 * 
	 * @param 	array 	$line_arr 	Current line splitted by ' '.
	 * 
	 * @return 	bool  				True in case that has answer format, 
	 * 								false otherwise.
	 */
	public function isNewAnswer(array $line_arr)
	{
		$possible_answer_letters = $this->getPossibleAnswerLetters();

		if (count($line_arr) < 2) {
			return false;
		}

		$answer_parenthesis = $line_arr[0][1] ?? '';
		$answer_letter = $line_arr[0][0] ?? '';

		if (
			$answer_parenthesis == ')'
			&& in_array($answer_letter, $possible_answer_letters)
		) {
			$answer_text = implode(' ', array_slice($line_arr, 1));
			$this->getTestSection()
				->getTestQuestion()
				->addAnswer($answer_text);
			return true;
		}

		return false;
	}

	/**
	 * Method that check if the line_arr passed has the format of a question,
	 * if so, create the TestQuestion and add it to TestSection and return 
	 * true, if not, only returns false.
	 * 
	 * @param 	array 	$line_arr 	Current line splitted by ' '.
	 * 
	 * @return 	bool  				True in case that has question format, 
	 * 								false otherwise.
	 */
	public function isNewQuestion(array $line_arr)
	{
		if (count($line_arr) < 3) {
			return false;
		}

		$slashes = ['–', '-'];

		$is_new_question = is_numeric($line_arr[0])
			&& in_array($line_arr[1], $slashes);
		if (!$is_new_question) { // NEW QUESTION
			return false;
		}
		$question = new TestQuestion();
		$question->setQuestion($line_arr[2]);
		$this->getTestSection()->addQuestion($question);
		return true;
	}

	/**
	 * Method that return the title of section in case that the line has 
	 * section format (should starts with "ESPECIALIDAD JURÍDICA EN").
	 * 
	 * @param 	string $line 			Line to check format
	 * 
	 * @return 	string $section_title	The title in case match the format, 
	 * 									empty string otherwise.
	 */
	public function isNewSection(string $line): string
	{
		$line_arr = explode(' ', $line);
		$section_title = ($line_arr[0] ?? '')
			. ' '
			. ($line_arr[1] ?? '')
			. ' '
			. ($line_arr[2] ?? '');
		return $section_title == 'ESPECIALIDAD JURÍDICA EN'
			? implode(' ', array_slice($line_arr, 3))
			: '';
	}

	public function getPossibleAnswerLetters(): array
	{
		return $this->possible_answer_letters;
	}

	public function getTestSection(): TestSection
	{
		$last_index = count($this->test_sections) - 1;
		return $this->test_sections[$last_index];
	}

	public function createTestSection($section_name = 'comunes')
	{
		$test_section = new TestSection($section_name);
		$this->addTestSection($test_section);
	}

	public function getLastTypeCreated()
	{
		return $this->last_type_created;
	}

	public function setLastTypeCreated($type = '')
	{
		$this->last_type_created = $type;
		return $this;
	}

	public function addTestSection(TestSection $test_section): self
	{
		$this->test_sections[] = $test_section;
		return $this;
	}

	public function getFileName(): string
	{
		return $this->file_name;
	}

	public function getAllTestSections()
	{
		return $this->test_sections;
	}

	/**
	 * Method to print the content of TestSection -> TestQuestions (and 
	 * answers).
	 * 
	 * @return void
	 */
	public function printFileContent()
	{
		$sections = $this->getAllTestSections();
		foreach ($sections as $section) {
			echo $section->getName() . "\n";
			$questions = $section->getAllQuestions();
			foreach ($questions as $question) {
				echo '--' . $question->getQuestion() . "\n";
				$answers = $question->getAnswers();
				foreach ($answers as $answer) {
					echo '-- --' . $answer . "\n";
				}
			}
		}
	}

	public function getCorrectAnswers()
	{
		return $this->correct_answers_by_section;
	}

	public function getArrayFileContent()
	{
		$json_data = [];
		$correct_answers = $this->getCorrectAnswers();
		$sections = $this->getAllTestSections();
		foreach ($sections as $s_i => $section) {
			$section_name = $section->getName();
			$json_data[$section_name] = [];
			$questions = $section->getAllQuestions();
			foreach ($questions as $q_i => $question) {
				$question_text = $question->getQuestion();
				$json_data[$section_name][] = [
					'pregunta' => $question_text,
					'respuestaCorrecta' => (int) $correct_answers[$s_i][$q_i],
					'respuestas' => []
				];
				$answers = $question->getAnswers();
				foreach ($answers as $answer) {
					$json_data[$section_name][$q_i]['respuestas'][] = $answer;
				}
			}
		}

		$json_string = json_encode(
			$json_data,
			JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT
		);

		return $json_string;
	}
}
