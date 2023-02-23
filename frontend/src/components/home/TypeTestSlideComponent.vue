<script>
export default {
	data() {
		return {
			items: [
				{
					year: 2022,
					selected: false
				},
				{
					year: 2021,
					selected: false
				}
			],
		}
	},
}
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
						Test por modalidad
					</strong>
				</div>
				<p class="text-subtitle-1">
					Responde a las preguntas específicas de una materia en concreto, o 
					con las preguntas comunes.
				</p>
				<v-chip-group
					selected-class="active-chip-brown"
					column
				>
					<v-chip
						v-for="(item, i) in items"
						:key="i"
						size="large"
					>
						{{ item.year }}
					</v-chip>
				</v-chip-group>
			</div>
		</div>
	</v-sheet>
</template>