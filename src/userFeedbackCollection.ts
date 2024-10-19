import * as vscode from 'vscode';

interface Feedback {
    suggestionId: string;
    rating: 'thumbs-up' | 'thumbs-down';
    timestamp: Date;
    userId?: string;
}

interface FeedbackSummary {
    thumbsUp: number;
    thumbsDown: number;
}

export class UserFeedbackCollection {
    private readonly feedbacksBySuggestionId: Map<string, Feedback[]> = new Map();

    addFeedback(suggestionId: string, rating: 'thumbs-up' | 'thumbs-down', userId?: string): void {
        if (!suggestionId.trim()) {
            throw new Error('Suggestion ID cannot be empty.');
        }

        const feedback: Feedback = {
            suggestionId,
            rating,
            timestamp: new Date(),
            userId,
        };

        const existingFeedbacks = this.feedbacksBySuggestionId.get(suggestionId) || [];
        existingFeedbacks.push(feedback);
        this.feedbacksBySuggestionId.set(suggestionId, existingFeedbacks);
    }

    getFeedbackBySuggestionId(suggestionId: string): Feedback[] {
        return this.feedbacksBySuggestionId.get(suggestionId) || [];
    }

    getFeedbackSummary(suggestionId: string): FeedbackSummary {
        if (!this.feedbacksBySuggestionId.has(suggestionId)) {
            return { thumbsUp: 0, thumbsDown: 0 };
        }

        return this.getFeedbackBySuggestionId(suggestionId).reduce(
            (summary, feedback) => {
                feedback.rating === 'thumbs-up' ? summary.thumbsUp++ : summary.thumbsDown++;
                return summary;
            },
            { thumbsUp: 0, thumbsDown: 0 }
        );
    }

    clearFeedback(): void {
        this.feedbacksBySuggestionId.clear();
    }
}