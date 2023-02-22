<script setup>
const props = defineProps({
	title: String,
	text: String,
	button: Object
})
</script>

<template>
	<v-sheet
		height="80%"
		color="transparent"
	>
		<div class="fill-height d-flex flex-column justify-space-between">
			<div>
				<div class="text-h4 mb-4">
					<strong>
						{{ title }}
					</strong>
				</div>
				<p class="text-subtitle-1">{{ text }}</p>
			</div>
			<div>
				<v-btn 
					class="main-white-button"
					:rounded="0" 
					append-icon="mdi-chevron-right"
				>
					{{ button.text }}
				</v-btn>
			</div>
		</div>
	</v-sheet>
</template>

<style>
	
</style>