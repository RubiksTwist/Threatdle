from __future__ import annotations

from threatdle.normalize.text import clean_attack_text, contains_any_name_reference, extract_first_observed_year


def test_clean_attack_text_strips_markdown_citations_and_tags():
    value = (
        "[Crutch](https://attack.mitre.org/software/S0538) uses <code>OneDrive</code> for exfiltration. "
        "(Citation: ESET Crutch December 2020)"
    )
    assert clean_attack_text(value) == "Crutch uses OneDrive for exfiltration."


def test_extract_first_observed_year_from_attack_description():
    value = (
        "[Turla](https://attack.mitre.org/groups/G0010) is a cyber espionage threat group that has compromised "
        "victims in over 50 countries since at least 2004.(Citation: Example)"
    )
    assert extract_first_observed_year(value) == 2004


def test_contains_any_name_reference_matches_display_name_tokens():
    assert contains_any_name_reference("This malware has been used by Sandworm Team since 2016.", ["Sandworm Team"])
    assert contains_any_name_reference("The operator is APT28.", ["APT28"])
    assert contains_any_name_reference("This malware is associated with menuPass.", ["menuPass"])
    assert contains_any_name_reference("This malware is associated with APT 28.", ["APT28"]) is False
