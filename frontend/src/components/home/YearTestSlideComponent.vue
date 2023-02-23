<script setup>
import {ref} from 'vue'
import { testType } from '../../stores/testType'

const testTypeStore = testType()

const yearSelected = ref(undefined)

const items = ref([
	{
		year: 2022,
		selected: false
	},
	{
		year: 2021,
		selected: false
	}
])
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
						Test por año
					</strong>
				</div>
				<p class="text-subtitle-1">
					Practica tu conocimiento con los exámenes oficiales de cada año.
				</p>
				<v-chip-group
					selected-class="active-chip-brown"
					column
					v-model="yearSelected"
					@update:model-value="testTypeStore.setType(yearSelected)"
				>
					<v-chip
						v-for="(item, i) in items"
						:key="i"
						:value="item.year"
						size="large"
					>
						{{ item.year }}
					</v-chip>
				</v-chip-group>
			</div>
		</div>
	</v-sheet>
</template>