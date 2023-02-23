import { defineStore } from "pinia";

export const testType = defineStore("testType", {
  state: () => ({
    type: undefined,
    year: undefined,
    modality: undefined,
  }),

  actions: {
    setType(value, year = undefined) {
      this.type = value;
      this.year = year;
    },
  },
});
