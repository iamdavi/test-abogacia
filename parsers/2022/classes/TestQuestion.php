<?php

class TestQuestion
{
	private $question;
	private $answers;

	public function __construct()
	{
		$this->question = '';
		$this->answers = [];
	}

	/**
	 * Method to append string to the last answer.
	 * 
	 * @param 	string 	$answer_string 	Text to appent to the last answer.
	 * 
	 * @return 	void
	 */
	public function appendAnswerString(string $answer_string = ''): void
	{
		$answers = $this->getAnswers();
		$last_index = count($answers) ? count($answers) - 1 : 0;
		$current_answer_content = $answers[$last_index];
		$answer_content = $current_answer_content . $answer_string;
		$this->modifyAnswer($last_index, $answer_content);
	}

	/**
	 * Method to append string to question.
	 * 
	 * @param 	string 	$answer_string 	Text to appent to question,
	 * 
	 * @return 	void
	 */
	public function appendQuestionString(string $question_string = '')
	{
		$current_question_content = $this->getQuestion();
		$full_question = $current_question_content . $question_string;
		$this->setQuestion($full_question);
	}

	/**
	 * Method that set the answer to a given index.
	 * 
	 * @param 	int 	$index		Index of answer to modify
	 * @param 	string	$answer 	Text of answer
	 * 
	 * @return 	self
	 */
	public function modifyAnswer(int $index, string $answer)
	{
		$this->answers[$index] = $answer;
		return $this;
	}

	public function setQuestion(string $question)
	{
		$this->question = $question;
		return $this;
	}

	public function getQuestion(): string
	{
		return $this->question;
	}

	public function getAnswers(): array
	{
		return $this->answers;
	}

	public function addAnswer(string $answer_text)
	{
		$this->answers[] = $answer_text;
		return $this;
	}

	public function hasQuestion(): bool
	{
		return $this->question != '';
	}
}
