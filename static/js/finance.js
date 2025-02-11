
function makeCashFlow(trsDate, amount, transactions) {

    const initialInvestment = {
        date: trsDate,
        amount: -Math.abs(Number(amount))
    };

    const transactionArray = transactions
        .filter(item => ['sell', 'dividend', 'redeem', 'interest', 'capReduct'].includes(item.transaction_type)) 
        .map(item => ({
        date: item.date,
        amount: Number(item.amount)
        }));

    const filteredArray = [initialInvestment, ...transactionArray];
    filteredArray.sort((a, b) => new Date(a.date) - new Date(b.date));
    return filteredArray;
}

function xirr(data) {
    // 데이터를 날짜와 금액으로 정리
    const dates = data.map(d => new Date(d.date));
    const amounts = data.map(d => d.amount);

    // 시작 날짜와 끝 날짜
    const startDate = dates[0];
    const endDate = dates[dates.length - 1];

    // 날짜를 일수로 변환
    const daysBetween = (start, end) => (end - start) / (1000 * 60 * 60 * 24);

    // IRR을 찾는 함수 (Newton-Raphson 방법)
    const npv = (rate) => {
        let result = 0;
        for (let i = 0; i < data.length; i++) {
        const time = daysBetween(startDate, dates[i]) / 365; // 연도 단위로 변환
        result += amounts[i] / Math.pow(1 + rate, time);
        }
        return result;
    };

    // XIRR을 찾기 위한 반복적 방법
    let guess = 0.1; // 초기 추정값
    let tolerance = 1e-6; // 오차 범위
    let iteration = 0;
    let maxIterations = 1000;

    // 반복적으로 NPV가 0에 가까워질 때까지 IRR을 찾는다.
    while (iteration < maxIterations) {
    const f = npv(guess);
    const fPrime = (npv(guess + tolerance) - f) / tolerance; // 유도된 함수

    const newGuess = guess - f / fPrime; // Newton-Raphson 공식

    if (Math.abs(newGuess - guess) < tolerance) {
        return newGuess * 100; // 백분율로 반환
    }

    guess = newGuess;
    iteration++;
    }

    return NaN; // 결과를 찾을 수 없을 때
}
