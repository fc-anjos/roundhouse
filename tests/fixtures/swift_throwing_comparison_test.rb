# A throwing expression remains a comparison operand after lowering assert_equal.
class ThrowingComparisonTest < Minitest::Test
  def test_throwing_right_operand
    assert_equal "a b", ActionDispatch::Router.decode_capture("a%20b")
  end

  def test_throwing_left_operand
    assert_equal ActionDispatch::Router.decode_capture("a%2Fb"), "a/b"
  end

  def test_two_throwing_operands
    assert_equal ActionDispatch::Router.decode_capture("jos%C3%A9"), ActionDispatch::Router.decode_capture("josé")
  end
end
