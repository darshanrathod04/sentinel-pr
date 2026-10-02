package com.sentinelpr.benchmark.model;

public class ConfusionMatrix {

    private int truePositives;
    private int falsePositives;
    private int trueNegatives;
    private int falseNegatives;

    public ConfusionMatrix() {}

    public ConfusionMatrix(int tp, int fp, int tn, int fn) {
        this.truePositives = tp;
        this.falsePositives = fp;
        this.trueNegatives = tn;
        this.falseNegatives = fn;
    }

    public void incrementTP() { truePositives++; }
    public void incrementFP() { falsePositives++; }
    public void incrementTN() { trueNegatives++; }
    public void incrementFN() { falseNegatives++; }

    public int getTruePositives() { return truePositives; }
    public int getFalsePositives() { return falsePositives; }
    public int getTrueNegatives() { return trueNegatives; }
    public int getFalseNegatives() { return falseNegatives; }

    public int getTotalCases() {
        return truePositives + falsePositives + trueNegatives + falseNegatives;
    }

    public double getPrecision() {
        int denominator = truePositives + falsePositives;
        if (denominator == 0) {
            return (falseNegatives == 0) ? 1.0 : 0.0;
        }
        return (double) truePositives / denominator;
    }

    public double getRecall() {
        int denominator = truePositives + falseNegatives;
        if (denominator == 0) {
            return 1.0;
        }
        return (double) truePositives / denominator;
    }

    public double getF1Score() {
        double p = getPrecision();
        double r = getRecall();
        if (p + r == 0.0) {
            return 0.0;
        }
        return 2.0 * (p * r) / (p + r);
    }

    public double getFalsePositiveRate() {
        int denominator = falsePositives + trueNegatives;
        if (denominator == 0) {
            return 0.0;
        }
        return (double) falsePositives / denominator;
    }

    public double getFalseNegativeRate() {
        int denominator = falseNegatives + truePositives;
        if (denominator == 0) {
            return 0.0;
        }
        return (double) falseNegatives / denominator;
    }
}
