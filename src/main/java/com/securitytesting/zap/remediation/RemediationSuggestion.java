package com.securitytesting.zap.remediation;

import java.util.ArrayList;
import java.util.List;

/**
 * Represents a remediation suggestion for a detected vulnerability.
 * Provides detailed guidance on how to fix security issues.
 */
public class RemediationSuggestion {
    private String title;
    private String description;
    private List<String> steps;
    private List<String> codeExamples;
    private List<String> references;
    private String difficulty; // EASY, MODERATE, COMPLEX
    private int estimatedTimeInMinutes;
    private boolean automatedFix;
    private String automatedFixScript;

    /**
     * Creates a new remediation suggestion.
     */
    private RemediationSuggestion(Builder builder) {
        this.title = builder.title;
        this.description = builder.description;
        this.steps = builder.steps;
        this.codeExamples = builder.codeExamples;
        this.references = builder.references;
        this.difficulty = builder.difficulty;
        this.estimatedTimeInMinutes = builder.estimatedTimeInMinutes;
        this.automatedFix = builder.automatedFix;
        this.automatedFixScript = builder.automatedFixScript;
    }

    /**
     * Gets the title of the remediation suggestion.
     *
     * @return The title
     */
    public String getTitle() {
        return title;
    }

    /**
     * Gets the description of the remediation suggestion.
     *
     * @return The description
     */
    public String getDescription() {
        return description;
    }

    /**
     * Gets the steps to follow for remediation.
     *
     * @return The steps
     */
    public List<String> getSteps() {
        return new ArrayList<>(steps);
    }

    /**
     * Gets the code examples for remediation.
     *
     * @return The code examples
     */
    public List<String> getCodeExamples() {
        return new ArrayList<>(codeExamples);
    }

    /**
     * Gets the references for remediation.
     *
     * @return The references
     */
    public List<String> getReferences() {
        return new ArrayList<>(references);
    }

    /**
     * Gets the difficulty level of the remediation.
     *
     * @return The difficulty level
     */
    public String getDifficulty() {
        return difficulty;
    }

    /**
     * Gets the estimated time in minutes to implement the remediation.
     *
     * @return The estimated time in minutes
     */
    public int getEstimatedTimeInMinutes() {
        return estimatedTimeInMinutes;
    }

    /**
     * Checks if there is an automated fix available.
     *
     * @return True if an automated fix is available, false otherwise
     */
    public boolean hasAutomatedFix() {
        return automatedFix;
    }

    /**
     * Gets the automated fix script.
     *
     * @return The automated fix script, or null if not available
     */
    public String getAutomatedFixScript() {
        return automatedFixScript;
    }

    /**
     * Returns the remediation suggestion as formatted text.
     *
     * @return The formatted remediation suggestion
     */
    public String toFormattedText() {
        StringBuilder sb = new StringBuilder();
        
        sb.append("## ").append(title).append("\n\n");
        sb.append(description).append("\n\n");
        
        // Steps
        sb.append("### Steps to Fix\n\n");
        for (int i = 0; i < steps.size(); i++) {
            sb.append(String.format("%d. %s\n", i + 1, steps.get(i)));
        }
        sb.append("\n");
        
        // Code examples
        if (!codeExamples.isEmpty()) {
            sb.append("### Code Examples\n\n");
            for (String example : codeExamples) {
                sb.append("```\n").append(example).append("\n```\n\n");
            }
        }
        
        // Implementation details
        sb.append("### Implementation Details\n\n");
        sb.append("- **Difficulty**: ").append(difficulty).append("\n");
        sb.append("- **Estimated Time**: ").append(estimatedTimeInMinutes).append(" minutes\n");
        sb.append("- **Automated Fix Available**: ").append(automatedFix ? "Yes" : "No").append("\n\n");
        
        // References
        if (!references.isEmpty()) {
            sb.append("### References\n\n");
            for (String reference : references) {
                sb.append("- ").append(reference).append("\n");
            }
        }
        
        return sb.toString();
    }

    /**
     * Builder for remediation suggestions.
     */
    public static class Builder {
        private final String title;
        private String description;
        private List<String> steps;
        private List<String> codeExamples;
        private List<String> references;
        private String difficulty;
        private int estimatedTimeInMinutes;
        private boolean automatedFix;
        private String automatedFixScript;

        /**
         * Creates a new builder with the specified title.
         *
         * @param title The title
         */
        public Builder(String title) {
            this.title = title;
            this.steps = new ArrayList<>();
            this.codeExamples = new ArrayList<>();
            this.references = new ArrayList<>();
            this.difficulty = "MODERATE";
            this.estimatedTimeInMinutes = 30;
            this.automatedFix = false;
        }

        /**
         * Sets the description of the remediation suggestion.
         *
         * @param description The description
         * @return This builder
         */
        public Builder description(String description) {
            this.description = description;
            return this;
        }

        /**
         * Adds a step to the remediation suggestion.
         *
         * @param step The step
         * @return This builder
         */
        public Builder addStep(String step) {
            this.steps.add(step);
            return this;
        }

        /**
         * Sets all steps for the remediation suggestion.
         *
         * @param steps The steps
         * @return This builder
         */
        public Builder steps(List<String> steps) {
            this.steps = new ArrayList<>(steps);
            return this;
        }

        /**
         * Adds a code example to the remediation suggestion.
         *
         * @param codeExample The code example
         * @return This builder
         */
        public Builder addCodeExample(String codeExample) {
            this.codeExamples.add(codeExample);
            return this;
        }

        /**
         * Sets all code examples for the remediation suggestion.
         *
         * @param codeExamples The code examples
         * @return This builder
         */
        public Builder codeExamples(List<String> codeExamples) {
            this.codeExamples = new ArrayList<>(codeExamples);
            return this;
        }

        /**
         * Adds a reference to the remediation suggestion.
         *
         * @param reference The reference
         * @return This builder
         */
        public Builder addReference(String reference) {
            this.references.add(reference);
            return this;
        }

        /**
         * Sets all references for the remediation suggestion.
         *
         * @param references The references
         * @return This builder
         */
        public Builder references(List<String> references) {
            this.references = new ArrayList<>(references);
            return this;
        }

        /**
         * Sets the difficulty level of the remediation.
         *
         * @param difficulty The difficulty level (EASY, MODERATE, COMPLEX)
         * @return This builder
         */
        public Builder difficulty(String difficulty) {
            this.difficulty = difficulty;
            return this;
        }

        /**
         * Sets the estimated time in minutes to implement the remediation.
         *
         * @param estimatedTimeInMinutes The estimated time in minutes
         * @return This builder
         */
        public Builder estimatedTimeInMinutes(int estimatedTimeInMinutes) {
            this.estimatedTimeInMinutes = estimatedTimeInMinutes;
            return this;
        }

        /**
         * Sets whether an automated fix is available.
         *
         * @param automatedFix Whether an automated fix is available
         * @return This builder
         */
        public Builder automatedFix(boolean automatedFix) {
            this.automatedFix = automatedFix;
            return this;
        }

        /**
         * Sets the automated fix script.
         *
         * @param automatedFixScript The automated fix script
         * @return This builder
         */
        public Builder automatedFixScript(String automatedFixScript) {
            this.automatedFixScript = automatedFixScript;
            this.automatedFix = (automatedFixScript != null && !automatedFixScript.isEmpty());
            return this;
        }

        /**
         * Builds the remediation suggestion.
         *
         * @return The remediation suggestion
         */
        public RemediationSuggestion build() {
            return new RemediationSuggestion(this);
        }
    }
}
