import difflib
import json
import os.path
import re
from timeit import default_timer as timer

try:
    from faster_whisper import WhisperModel
except ImportError:
    WhisperModel = None
from loguru import logger

from app.config import config
from app.utils import utils

model_size = config.whisper.get("model_size", "large-v3")
device = config.whisper.get("device", "cpu")
compute_type = config.whisper.get("compute_type", "int8")
initial_prompt = config.whisper.get("initial_prompt", "") or None
model = None


def create(audio_file, subtitle_file: str = ""):
    global model
    if WhisperModel is None:
        logger.warning("faster_whisper not available, skipping whisper subtitle generation")
        return ""
    if not model:
        model_path = f"{utils.root_dir()}/models/whisper-{model_size}"
        model_bin_file = f"{model_path}/model.bin"
        if not os.path.isdir(model_path) or not os.path.isfile(model_bin_file):
            model_path = model_size

        logger.info(
            f"loading model: {model_path}, device: {device}, compute_type: {compute_type}"
        )
        try:
            model = WhisperModel(
                model_size_or_path=model_path, device=device, compute_type=compute_type
            )
        except Exception as e:
            logger.error(
                f"failed to load model: {e} \n\n"
                f"********************************************\n"
                f"this may be caused by network issue. \n"
                f"please download the model manually and put it in the 'models' folder. \n"
                f"see [README.md FAQ](https://github.com/harry0703/MoneyPrinterTurbo) for more details.\n"
                f"********************************************\n\n"
            )
            return None

    logger.info(f"start, output file: {subtitle_file}")
    if not subtitle_file:
        subtitle_file = f"{audio_file}.srt"

    segments, info = model.transcribe(
        audio_file,
        beam_size=5,
        word_timestamps=True,
        vad_filter=True,
        vad_parameters=dict(min_silence_duration_ms=500),
        **({"initial_prompt": initial_prompt} if initial_prompt else {}),
    )

    logger.info(
        f"detected language: '{info.language}', probability: {info.language_probability:.2f}"
    )

    start = timer()
    subtitles = []

    def recognized(seg_text, seg_start, seg_end):
        seg_text = seg_text.strip()
        if not seg_text:
            return

        msg = "[%.2fs -> %.2fs] %s" % (seg_start, seg_end, seg_text)
        logger.debug(msg)

        subtitles.append(
            {"msg": seg_text, "start_time": seg_start, "end_time": seg_end}
        )

    for segment in segments:
        words_idx = 0
        words_len = len(segment.words)

        seg_start = 0
        seg_end = 0
        seg_text = ""

        if segment.words:
            is_segmented = False
            for word in segment.words:
                if not is_segmented:
                    seg_start = word.start
                    is_segmented = True

                seg_end = word.end
                # If it contains punctuation, then break the sentence.
                seg_text += word.word

                if utils.str_contains_punctuation(word.word):
                    # remove last char
                    seg_text = seg_text[:-1]
                    if not seg_text:
                        continue

                    recognized(seg_text, seg_start, seg_end)

                    is_segmented = False
                    seg_text = ""

                if words_idx == 0 and segment.start < word.start:
                    seg_start = word.start
                if words_idx == (words_len - 1) and segment.end > word.end:
                    seg_end = word.end
                words_idx += 1

        if not seg_text:
            continue

        recognized(seg_text, seg_start, seg_end)

    end = timer()

    diff = end - start
    logger.info(f"complete, elapsed: {diff:.2f} s")

    idx = 1
    lines = []
    for subtitle in subtitles:
        text = subtitle.get("msg")
        if text:
            lines.append(
                utils.text_to_srt(
                    idx, text, subtitle.get("start_time"), subtitle.get("end_time")
                )
            )
            idx += 1

    sub = "\n".join(lines) + "\n"
    with open(subtitle_file, "w", encoding="utf-8") as f:
        f.write(sub)
    logger.info(f"subtitle file created: {subtitle_file}")


def file_to_subtitles(filename):
    if not filename or not os.path.isfile(filename):
        return []

    times_texts = []
    current_times = None
    current_text = ""
    index = 0
    with open(filename, "r", encoding="utf-8") as f:
        for line in f:
            times = re.findall("([0-9]*:[0-9]*:[0-9]*,[0-9]*)", line)
            if times:
                current_times = line
            elif line.strip() == "" and current_times:
                index += 1
                times_texts.append((index, current_times.strip(), current_text.strip()))
                current_times, current_text = None, ""
            elif current_times:
                current_text += line

    # Flush the final block. SRT files whose last subtitle is not followed by a
    # trailing blank line never hit the blank-line branch above, so without this
    # the last subtitle would be silently dropped.
    if current_times:
        index += 1
        times_texts.append((index, current_times.strip(), current_text.strip()))
    return times_texts


def levenshtein_distance(s1, s2):
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)

    if len(s2) == 0:
        return len(s1)

    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row

    return previous_row[-1]


def similarity(a, b):
    distance = levenshtein_distance(a.lower(), b.lower())
    max_length = max(len(a), len(b))
    return 1 - (distance / max_length)


SUBTITLE_CORRECTION_MODE_PROFILED = "profiled"


class SubtitleCorrectionError(Exception):
    """Fail-closed caption correction/validation failure (profiled mode)."""


def _srt_time_to_seconds(value: str) -> float:
    match = re.fullmatch(r"(\d+):(\d+):(\d+),(\d+)", value.strip())
    if not match:
        raise SubtitleCorrectionError("unparseable srt timestamp")
    hours, minutes, seconds, millis = (int(part) for part in match.groups())
    return hours * 3600 + minutes * 60 + seconds + millis / 1000.0


def _seconds_to_srt_time(value: float) -> str:
    millis = int(round(value * 1000.0))
    hours, remainder = divmod(millis, 3600000)
    minutes, remainder = divmod(remainder, 60000)
    seconds, millis = divmod(remainder, 1000)
    return f"{hours:02d}:{minutes:02d}:{seconds:02d},{millis:03d}"


def _caption_similarity(a: str, b: str) -> float:
    return difflib.SequenceMatcher(
        None, a.lower().split(), b.lower().split()
    ).ratio()


def _align_script_lines_to_whisper(whisper_cues, script_lines):
    """Partition whisper cues into one consecutive non-empty group per
    script line, minimizing total wording distance.

    Whisper timings stay authoritative: every whisper cue is used exactly
    once, in order; no interval is created, reordered, or erased. Each
    script line inherits the union of its group's cue timings, so the
    emitted cues are monotonic, positive-duration, and cover the full
    narration, including the final spoken stanza.
    """
    n_cues = len(whisper_cues)
    n_lines = len(script_lines)
    if n_cues < n_lines:
        raise SubtitleCorrectionError(
            "insufficient whisper timing coverage for the staged script"
        )

    infinity = float("inf")
    texts = [cue[2] for cue in whisper_cues]
    # dp[k][j] = minimum total distance aligning the first k script lines
    # to the first j whisper cues; back[k][j] = start index of the group
    # assigned to line k in that optimum.
    dp = [[infinity] * (n_cues + 1) for _ in range(n_lines + 1)]
    back = [[-1] * (n_cues + 1) for _ in range(n_lines + 1)]
    dp[0][0] = 0.0
    for k in range(1, n_lines + 1):
        line = script_lines[k - 1]
        # j must leave at least (n_lines - k) cues for the remaining lines.
        for j in range(k, n_cues - (n_lines - k) + 1):
            combined = ""
            for i in range(j - 1, k - 2, -1):
                combined = texts[i] if not combined else texts[i] + " " + combined
                candidate = dp[k - 1][i] + (1.0 - _caption_similarity(line, combined))
                if candidate < dp[k][j]:
                    dp[k][j] = candidate
                    back[k][j] = i

    if dp[n_lines][n_cues] == infinity:
        raise SubtitleCorrectionError(
            "whisper timing cannot be aligned to the staged script"
        )

    groups = []
    j = n_cues
    for k in range(n_lines, 0, -1):
        i = back[k][j]
        groups.append((i, j))
        j = i
    groups.reverse()

    aligned = []
    for (i, j), line in zip(groups, script_lines):
        aligned.append((whisper_cues[i][0], whisper_cues[j - 1][1], line))
    return aligned


def _validate_profiled_cues(cues, narration_end, script_lines):
    """Fail-closed caption validation for the profiled correction path."""
    problems = []
    if len(cues) != len(script_lines):
        problems.append("cue count does not match the staged script lines")
    previous_end = 0.0
    for index, (start, end, text) in enumerate(cues):
        if not text.strip():
            problems.append(f"cue {index + 1} has empty text")
        if not start < end:
            problems.append(f"cue {index + 1} is zero-duration or reversed")
        if start < previous_end:
            problems.append(f"cue {index + 1} is not monotonic")
        if start < 0.0 or end > narration_end + 0.01:
            problems.append(f"cue {index + 1} is outside narration duration")
        previous_end = end
    if cues and cues[-1][1] < narration_end - 0.05:
        problems.append("captions do not reach the final spoken stanza")
    if problems:
        raise SubtitleCorrectionError("; ".join(problems))


def _correct_profiled(subtitle_file, video_script):
    """Profiled caption correction (braintrustcrypto briefing profile).

    Aligns the exact staged-script text to authoritative whisper timings
    via a global monotonic partition, then validates every cue before
    writing. Any failure raises SubtitleCorrectionError so the render
    aborts before video generation. Never emits zero-duration,
    non-monotonic, out-of-range, empty, or tail-truncated captions.
    """
    subtitle_items = file_to_subtitles(subtitle_file)
    normalized_script = utils.normalize_script_for_subtitle_matching(video_script)
    script_lines = [
        line.strip()
        for line in utils.split_string_by_punctuations(normalized_script)
        if line.strip()
    ]
    if not script_lines:
        logger.info("profiled caption correction: empty script, nothing to correct")
        return
    if not subtitle_items:
        raise SubtitleCorrectionError("whisper produced no timed cues")

    whisper_cues = []
    previous_end = 0.0
    for _, times, text in subtitle_items:
        start_raw, end_raw = times.split(" --> ")
        start = _srt_time_to_seconds(start_raw)
        end = _srt_time_to_seconds(end_raw)
        text = text.strip()
        if not text or not start < end or start < previous_end:
            raise SubtitleCorrectionError(
                "whisper timing is unusable for profiled correction"
            )
        whisper_cues.append((start, end, text))
        previous_end = end

    aligned = _align_script_lines_to_whisper(whisper_cues, script_lines)
    narration_end = whisper_cues[-1][1]
    _validate_profiled_cues(aligned, narration_end, script_lines)

    with open(subtitle_file, "w", encoding="utf-8") as fd:
        for index, (start, end, text) in enumerate(aligned):
            fd.write(
                f"{index + 1}\n"
                f"{_seconds_to_srt_time(start)} --> {_seconds_to_srt_time(end)}\n"
                f"{text}\n\n"
            )
    logger.info("Subtitle corrected (profiled alignment)")


def correct(subtitle_file, video_script, correction_mode=None):
    if correction_mode == SUBTITLE_CORRECTION_MODE_PROFILED:
        _correct_profiled(subtitle_file, video_script)
        return

    subtitle_items = file_to_subtitles(subtitle_file)
    normalized_script = utils.normalize_script_for_subtitle_matching(video_script)
    script_lines = utils.split_string_by_punctuations(normalized_script)

    corrected = False
    new_subtitle_items = []
    script_index = 0
    subtitle_index = 0

    while script_index < len(script_lines) and subtitle_index < len(subtitle_items):
        script_line = script_lines[script_index].strip()
        subtitle_line = subtitle_items[subtitle_index][2].strip()

        if script_line == subtitle_line:
            new_subtitle_items.append(subtitle_items[subtitle_index])
            script_index += 1
            subtitle_index += 1
        else:
            combined_subtitle = subtitle_line
            start_time = subtitle_items[subtitle_index][1].split(" --> ")[0]
            end_time = subtitle_items[subtitle_index][1].split(" --> ")[1]
            next_subtitle_index = subtitle_index + 1

            while next_subtitle_index < len(subtitle_items):
                next_subtitle = subtitle_items[next_subtitle_index][2].strip()
                if similarity(
                    script_line, combined_subtitle + " " + next_subtitle
                ) > similarity(script_line, combined_subtitle):
                    combined_subtitle += " " + next_subtitle
                    end_time = subtitle_items[next_subtitle_index][1].split(" --> ")[1]
                    next_subtitle_index += 1
                else:
                    break

            if similarity(script_line, combined_subtitle) > 0.8:
                logger.warning(
                    f"Merged/Corrected - Script: {script_line}, Subtitle: {combined_subtitle}"
                )
                new_subtitle_items.append(
                    (
                        len(new_subtitle_items) + 1,
                        f"{start_time} --> {end_time}",
                        script_line,
                    )
                )
                corrected = True
            else:
                logger.warning(
                    f"Mismatch - Script: {script_line}, Subtitle: {combined_subtitle}"
                )
                new_subtitle_items.append(
                    (
                        len(new_subtitle_items) + 1,
                        f"{start_time} --> {end_time}",
                        script_line,
                    )
                )
                corrected = True

            script_index += 1
            subtitle_index = next_subtitle_index

    # Process the remaining lines of the script.
    while script_index < len(script_lines):
        logger.warning(f"Extra script line: {script_lines[script_index]}")
        if subtitle_index < len(subtitle_items):
            new_subtitle_items.append(
                (
                    len(new_subtitle_items) + 1,
                    subtitle_items[subtitle_index][1],
                    script_lines[script_index],
                )
            )
            subtitle_index += 1
        else:
            new_subtitle_items.append(
                (
                    len(new_subtitle_items) + 1,
                    "00:00:00,000 --> 00:00:00,000",
                    script_lines[script_index],
                )
            )
        script_index += 1
        corrected = True

    if corrected:
        with open(subtitle_file, "w", encoding="utf-8") as fd:
            for i, item in enumerate(new_subtitle_items):
                fd.write(f"{i + 1}\n{item[1]}\n{item[2]}\n\n")
        logger.info("Subtitle corrected")
    else:
        logger.success("Subtitle is correct")


if __name__ == "__main__":
    task_id = "c12fd1e6-4b0a-4d65-a075-c87abe35a072"
    task_dir = utils.task_dir(task_id)
    subtitle_file = f"{task_dir}/subtitle.srt"
    audio_file = f"{task_dir}/audio.mp3"

    subtitles = file_to_subtitles(subtitle_file)
    print(subtitles)

    script_file = f"{task_dir}/script.json"
    with open(script_file, "r") as f:
        script_content = f.read()
    s = json.loads(script_content)
    script = s.get("script")

    correct(subtitle_file, script)

    subtitle_file = f"{task_dir}/subtitle-test.srt"
    create(audio_file, subtitle_file)
