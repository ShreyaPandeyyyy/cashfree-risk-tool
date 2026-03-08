function riskScore(rules) {

  let riskScore = 0;

  rules.forEach(rule => {

    const severity = (rule.severity || "").toLowerCase();

    if (severity === "high") {
      riskScore += 6;
    }

    else if (severity === "medium") {
      riskScore += 3;
    }

    else if (severity === "low") {
      riskScore += 1;
    }

  });

  /* -----------------------------
     Trust score calculation
  ----------------------------- */

  let trustScore = 100 - (riskScore * 5);

  if (trustScore < 0) {
    trustScore = 0;
  }

  /* -----------------------------
     Risk level
  ----------------------------- */

  let riskLevel = "Low Risk";

  if (riskScore >= 10) {
    riskLevel = "High Risk";
  }

  else if (riskScore >= 5) {
    riskLevel = "Medium Risk";
  }

  return {
    riskScore,
    trustScore,
    riskLevel
  };
}

module.exports = riskScore;