function updateLengthLabel() {
  const length = document.getElementById('length').value
  document.getElementById('lengthValue').textContent = length
}

function generatePassword() {
  const length = parseInt(document.getElementById('length').value)
  const includeLower = document.getElementById('includeLower').checked
  const includeUpper = document.getElementById('includeUpper').checked
  const includeNumbers = document.getElementById('includeNumbers').checked
  const includeSymbols = document.getElementById('includeSymbols').checked

  let chars = ''
  if (includeLower) chars += 'abcdefghijklmnopqrstuvwxyz'
  if (includeUpper) chars += 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
  if (includeNumbers) chars += '0123456789'
  if (includeSymbols) chars += '!@#$%^&*()_+-=[]{}|;:,.<>?'

  if (chars.length === 0) {
    document.getElementById('password').textContent =
      '⚠️ 최소 하나의 옵션을 선택하세요.'
    return
  }

  let password = ''
  for (let i = 0; i < length; i++) {
    password += chars[Math.floor(Math.random() * chars.length)]
  }

  document.getElementById('password').textContent = password
}

function copyPassword() {
  const password = document.getElementById('password').textContent
  if (!password || password.includes('⚠️')) return

  navigator.clipboard
    .writeText(password)
    .then(() => alert('📋 클립보드에 복사되었습니다!'))
    .catch(() => alert('❌ 복사 실패!'))
}
