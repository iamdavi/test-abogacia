<?php

include_once(__DIR__ . '\.\TestQuestion.php');

class TestSection
{
	private $name;
	private $questions;

	public function __construct(string $section_name = '')
	{
		$this->name = $section_name;
		$this->questions = [];
	}

	public function getTestQuestion()
	{
		$last_index = count($this->questions) - 1;
		return $this->questions[$last_index];
	}

	public function addQuestion(TestQuestion $test_question)
	{
		$this->questions[] = $test_question;
		return $this;
	}

	public function getAllQuestions()
	{
		return $this->questions;
	}

	public function getName()
	{
		return $this->name;
	}
}
