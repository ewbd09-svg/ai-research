/**
 * 共享作弊检测 + 评分引擎
 * 所有 Workflow 通过 @actions/github-script 的 eval 方式引用
 */
const cheatDetect = {
  // ---- 检测规则 ----
  patterns: [
    // 危险函数
    { regex: /shell\s*=\s*True/g,         name: 'shell=True',           conf: 0.9,  desc: 'use shell=True in subprocess' },
    { regex: /eval\s*\(/g,                 name: 'eval()',              conf: 0.8,  desc: 'use eval() dynamic execution' },
    { regex: /exec\s*\(/g,                 name: 'exec()',              conf: 0.85, desc: 'use exec() dynamic execution' },
    { regex: /pickle\.loads\s*\(/g,        name: 'pickle.loads()',      conf: 0.85, desc: 'unsafe deserialization' },
    { regex: /os\.system\s*\(/g,           name: 'os.system()',         conf: 0.8,  desc: 'shell command execution' },
    { regex: /os\.popen\s*\(/g,            name: 'os.popen()',          conf: 0.8,  desc: 'shell command execution' },
    { regex: /subprocess\.[a-z]+/g,        name: 'subprocess.*()',      conf: 0.7,  desc: 'unsafe subprocess call' },
    // 硬编码
    { regex: /is_admin\s*=\s*True/g,       name: 'is_admin_hardcoded',  conf: 0.75, desc: 'hardcoded admin privilege' },
    { regex: /execute\s*\(\s*f["\u201c]/g, name: 'sql_fstring',         conf: 0.85, desc: 'f-string SQL injection' },
    { regex: /(password|secret|api_key|token)\s*[=:]\s*["'`][^"'`$]{8,}["'`]/gi, name: 'hardcoded_secret', conf: 0.95, desc: 'hardcoded credential' },
    // AI 生成模式
    { regex: /Here['s] (a|the|my) (fix|solution|implementation)/gi, name: 'AI_greeting', conf: 0.2, desc: 'AI pattern' },
    { regex: /I['\u2019]ll (provide|implement|create|write|add)/gi,  name: 'AI_ill_provide', conf: 0.15, desc: 'AI pattern' },
    { regex: /Sure[!,] (here|I)/gi,       name: 'AI_sure_here',        conf: 0.15, desc: 'AI pattern' },
    { regex: /(Certainly|Absolutely|Of course)[!,]/gi, name: 'AI_certainly', conf: 0.15, desc: 'AI pattern' },
    { regex: /Let me (know if|explain|provide|show)/gi, name: 'AI_let_me', conf: 0.12, desc: 'AI pattern' },
    // 加密货币/挖矿
    { regex: /mine\s*\(/gi,                name: 'crypto_mining',       conf: 0.9,  desc: 'cryptocurrency mining' },
    { regex: /cryptonight|ethash|randomx/gi, name: 'mining_algorithm',  conf: 0.95, desc: 'mining algorithm' },
  ],

  // ---- AST 语义分析 ----
  astAnalyze(code) {
    const findings = [];
    try {
      // Check for obfuscation: concatenation of dangerous function names
      const obfuscationPatterns = [
        { pat: /(['"`]ev['"`\)]\s*\+\s*['"`]al['"`])/, name: 'obfuscated_eval', weight: 0.7 },
        { pat: /String\.fromCharCode/, name: 'string_fromcharcode', weight: 0.3 },
        { pat: /atob\s*\(/, name: 'base64_decode', weight: 0.3 },
        { pat: /\\x65\\x76\\x61\\x6c/, name: 'hex_encoded_eval', weight: 0.8 },
      ];
      for (const { pat, name, weight } of obfuscationPatterns) {
        if (pat.test(code)) findings.push({ name, conf: weight, desc: `obfuscation: ${name}` });
      }

      // Check code structure
      if (code.length > 50) {
        const lines = code.split('\n').filter(l => l.trim());
        // No comments at all is suspicious
        const hasComments = /\/\/|#|<!--|\/\*/.test(code);
        const hasStrings = /['"`]/.test(code);
        const hasLogic = /\b(if|for|while|return|switch|try|catch)\b/.test(code);
        if (!hasComments && !hasStrings && !hasLogic && lines.length > 5) {
          findings.push({ name: 'minimal_code', conf: 0.3, desc: 'code has no comments, strings, or logic' });
        }
      }
    } catch (e) { /* ignore AST errors */ }
    return findings;
  },

  // ---- 难易度评分 ----
  scoreMap: { easy: 50, medium: 75, hard: 100, expert: 150 },

  // ---- 主入口 ----
  evaluate(code, { difficulty = 'medium', labels = [] } = {}) {
    const allFindings = [];

    // 1. Pattern matching
    for (const { regex, name, conf, desc } of this.patterns) {
      let match;
      regex.lastIndex = 0;
      if (regex.test(code)) {
        allFindings.push({ name, conf, desc });
      }
    }

    // 2. AST analysis
    const astFindings = this.astAnalyze(code);
    allFindings.push(...astFindings);

    // 3. Determine difficulty
    const allLabels = [...labels];
    let diff = difficulty;
    for (const d of ['easy', 'medium', 'hard', 'expert']) {
      if (allLabels.includes(d)) { diff = d; break; }
    }

    // 4. Calculate score
    const baseScore = this.scoreMap[diff] || 75;
    const suspicion = allFindings.length === 0 ? 0 :
      Math.min(Math.max(...allFindings.map(f => f.conf)), 1);
    const deduction = Math.floor(suspicion * 100);
    const total = Math.max(baseScore - deduction, 0);
    const clean = allFindings.length === 0;

    return { findings: allFindings, clean, score: total, baseScore, deduction, difficulty: diff };
  },

  // ---- 生成报告 ----
  formatReport(author, issueNum, { findings, clean, score, baseScore, difficulty }) {
    let report = '';
    if (clean) {
      report += `## ✅ 自动审查通过\n\n**提交者**: @${author}\n**任务**: #${issueNum}\n**难度**: ${difficulty}\n**结果**: 未检测到可疑模式。\n**得分**: **${score}/${baseScore}**\n\n`;
    } else {
      const details = findings.map(f =>
        `| ${f.name} | ${Math.floor(f.conf * 100)}% | ${f.desc} |`
      ).join('\n');
      report += `## ⚠️ 检测到可疑模式\n\n**提交者**: @${author}\n**任务**: #${issueNum}\n**难度**: ${difficulty}\n\n| 嫌疑项 | 置信度 | 说明 |\n|:------:|:------:|:----:|\n${details}\n\n**最终得分**: **${score}/${baseScore}** (作弊扣分 -${Math.floor((1 - score/baseScore) * 100)}%)\n\n`;
    }
    return report;
  }
};

// Make available
globalThis.cheatDetect = cheatDetect;
