typedef struct {
    int identifier;
    int flags;
} Record;

static int normalize_score(int score) {
    if (score < 0) {
        return 0;
    }
    if (score > 100) {
        return 100;
    }
    return score;
}

int evaluate_record(const Record *record, int score) {
    int normalized = normalize_score(score);
    if ((record->flags & 1) != 0) {
        return normalized + record->identifier;
    }
    return normalized - record->identifier;
}
