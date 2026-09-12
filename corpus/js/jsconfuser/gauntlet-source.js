const SAMPLES = [
  "the quick brown fox jumps over the lazy dog",
  "pack my box with five dozen liquor jugs",
  "how vexingly quick daft zebras jump",
];

const VOWELS = "aeiou";

function classifyCharacter(character) {
  if (VOWELS.indexOf(character) !== -1) {
    return "vowel";
  }
  if (character === " ") {
    return "space";
  }
  return "consonant";
}

function buildHistogram(sentence) {
  const histogram = { vowel: 0, consonant: 0, space: 0 };
  for (let index = 0; index < sentence.length; index = index + 1) {
    const kind = classifyCharacter(sentence[index]);
    histogram[kind] = histogram[kind] + 1;
  }
  return histogram;
}

function summarize(sentence) {
  const histogram = buildHistogram(sentence);
  const total = histogram.vowel + histogram.consonant + histogram.space;
  return {
    sentence: sentence,
    length: total,
    vowelRatio: total === 0 ? 0 : histogram.vowel / total,
    histogram: histogram,
  };
}

function pipeline(corpus) {
  const reports = [];
  for (let index = 0; index < corpus.length; index = index + 1) {
    reports.push(summarize(corpus[index]));
  }
  return reports;
}

const results = pipeline(SAMPLES);
for (let index = 0; index < results.length; index = index + 1) {
  const report = results[index];
  console.log(report.sentence, report.length, report.vowelRatio);
}
