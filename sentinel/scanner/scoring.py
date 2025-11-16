def compute_score(findings, rules):
    total = sum(r.weight for r in rules)
    done = 0

    for f in findings:
        rule = next(r for r in rules if r.id == f.id)
        if f.status == "pass":
            done += rule.weight

    return round(100 * done / total)

