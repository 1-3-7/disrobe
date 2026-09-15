defmodule EdgeCases do
  @moduledoc "Megafile exercising Elixir constructs for BEAM decompilation tests."

  @default_opts %{verbose: false, retries: 3, timeout: 5_000}

  defstruct [:id, :name, :email, tags: [], created_at: nil, meta: %{}]

  @type result(t) :: {:ok, t} | {:error, term()}
  @type id :: non_neg_integer()

  defmodule Address do
    @moduledoc false
    @enforce_keys [:street, :city]
    @derive {Inspect, only: [:city, :country]}
    defstruct [:street, :city, :zip, :country]
  end

  defmodule Greeter do
    @moduledoc false

    @callback greet(binary()) :: binary()
    @callback farewell(binary()) :: binary()

    defmacro __using__(_opts) do
      quote do
        @behaviour Greeter

        def hello(name), do: greet(name)
      end
    end
  end

  defprotocol Renderable do
    @fallback_to_any true
    def render(value)
  end

  defimpl Renderable, for: BitString do
    def render(s), do: "string:" <> s
  end

  defimpl Renderable, for: Integer do
    def render(n), do: "int:#{n}"
  end

  defimpl Renderable, for: List do
    def render(l), do: "list:" <> Enum.join(Enum.map(l, &Renderable.render/1), ",")
  end

  defimpl Renderable, for: Any do
    def render(_), do: "unknown"
  end

  def main do
    IO.puts("EdgeCases main")
    _ = pattern_match_basic({:ok, 42})
    _ = pipe_chain([1, 2, 3, 4, 5])
    _ = with_demo(%{a: 1, b: 2})
    :ok
  end

  def pattern_match_basic({:ok, value}), do: {:matched_ok, value}
  def pattern_match_basic({:error, reason}), do: {:matched_err, reason}
  def pattern_match_basic({:partial, [head | _tail]}), do: {:head, head}
  def pattern_match_basic(atom) when is_atom(atom), do: {:atom, atom}
  def pattern_match_basic(_), do: :no_match

  def pattern_match_map(%{type: :user, id: id, name: name}), do: {:user, id, name}
  def pattern_match_map(%{type: :admin} = m), do: {:admin, m}
  def pattern_match_map(%{} = empty) when map_size(empty) == 0, do: :empty
  def pattern_match_map(_), do: :other

  def pattern_match_struct(%__MODULE__{id: id, name: name}), do: {id, name}
  def pattern_match_struct(%Address{city: city}), do: {:addr, city}
  def pattern_match_struct(_), do: :no_struct

  def pipe_chain(list) do
    list
    |> Enum.map(&(&1 * 2))
    |> Enum.filter(&(&1 > 3))
    |> Enum.reduce(0, fn x, acc -> x + acc end)
  end

  def pipe_with_named(list) do
    list
    |> Enum.map(fn x -> x * x end)
    |> Enum.sort(&>=/2)
    |> Enum.take(3)
    |> Enum.sum()
  end

  def with_demo(map) do
    with {:ok, a} <- Map.fetch(map, :a),
         {:ok, b} <- Map.fetch(map, :b),
         true <- a + b > 0 do
      {:ok, a + b}
    else
      :error -> {:error, :missing_key}
      false -> {:error, :nonpositive}
      _ -> {:error, :unknown}
    end
  end

  def comprehension_simple(list) do
    for x <- list, x > 0, do: x * x
  end

  def comprehension_multi(xs, ys) do
    for x <- xs, y <- ys, x != y, do: {x, y}
  end

  def comprehension_into_map(pairs) do
    for {k, v} <- pairs, is_atom(k), is_integer(v), into: %{}, do: {k, v}
  end

  def comprehension_into_binary(list) do
    for n <- list, n in 0..255, into: <<>>, do: <<n::8>>
  end

  def stream_demo(list) do
    list
    |> Stream.map(&(&1 + 1))
    |> Stream.filter(&(rem(&1, 2) == 0))
    |> Stream.take(5)
    |> Enum.to_list()
  end

  def case_demo(x) do
    case x do
      {:ok, n} when n > 0 -> {:positive, n}
      {:ok, _} -> :zero_or_negative
      {:error, reason} -> {:err, reason}
      _ -> :default
    end
  end

  def cond_demo(x) do
    cond do
      x < 0 -> :negative
      x == 0 -> :zero
      x < 10 -> :small
      true -> :big
    end
  end

  def if_demo(x) do
    if x > 100 do
      :big
    else
      if x > 0 do
        :small
      else
        :zero_or_negative
      end
    end
  end

  def unless_demo(x) do
    unless x, do: :falsy, else: :truthy
  end

  def named_args_demo(name, opts \\ []) do
    verbose = Keyword.get(opts, :verbose, false)
    retries = Keyword.get(opts, :retries, 3)
    {name, verbose, retries}
  end

  def default_args(a, b \\ 10, c \\ 20) do
    a + b + c
  end

  def first_class_callable(fun, list) when is_function(fun, 1) do
    Enum.map(list, fun)
  end

  def capture_demo do
    add = &(&1 + &2)
    inc = &(&1 + 1)
    upcase = &String.upcase/1
    {add.(1, 2), inc.(5), upcase.("hi")}
  end

  def anonymous_multi_clause do
    fn
      {:ok, v} -> v
      {:error, _} -> nil
      :timeout -> :retry
    end
  end

  def map_update(m, k) do
    Map.update(m, k, 1, fn v -> v + 1 end)
  end

  def map_get_in(data) do
    get_in(data, [:user, :addr, :city])
  end

  def map_put_in(data) do
    put_in(data, [:user, :addr, :zip], "12345")
  end

  def map_update_in(data) do
    update_in(data, [:user, :count], &((&1 || 0) + 1))
  end

  def keyword_demo do
    kw = [a: 1, b: 2, c: 3]
    sum = kw |> Keyword.values() |> Enum.sum()
    keys = Keyword.keys(kw)
    {sum, keys}
  end

  def list_ops(list) do
    {Enum.sum(list), Enum.max(list), Enum.min(list), Enum.uniq(list)}
  end

  def tuple_destructure({a, b, c}), do: {c, b, a}
  def tuple_destructure({a, b, c, d}), do: {d, c, b, a}
  def tuple_destructure(t) when is_tuple(t), do: Tuple.to_list(t)

  def binary_pattern(<<0x89, "PNG", _rest::binary>>), do: :png
  def binary_pattern(<<0xFF, 0xD8, _rest::binary>>), do: :jpeg
  def binary_pattern(<<"GIF87a", _rest::binary>>), do: :gif87
  def binary_pattern(<<"GIF89a", _rest::binary>>), do: :gif89
  def binary_pattern(_), do: :unknown

  def binary_construct(tag, payload) when is_atom(tag) and is_binary(payload) do
    tag_bin = Atom.to_string(tag)
    tag_len = byte_size(tag_bin)
    len = byte_size(payload)
    <<1::8, tag_len::8, tag_bin::binary, len::32-big, payload::binary>>
  end

  def string_interp(name, age), do: "Hello, #{name}, you are #{age}"

  def sigil_demo do
    {~w(one two three), ~r/\d+/, ~s("quoted"), ~c"charlist", ~D[2026-05-25]}
  end

  def heredoc_demo do
    """
    Line one
    Line two
    Line three
    """
  end

  defmacro unless_macro(cond, do: do_block, else: else_block) do
    quote do
      if !unquote(cond), do: unquote(do_block), else: unquote(else_block)
    end
  end

  defmacro debug(expr) do
    quote do
      result = unquote(expr)
      IO.inspect(result, label: unquote(Macro.to_string(expr)))
      result
    end
  end

  def use_genserver do
    {:ok, pid} = GenServer.start_link(__MODULE__.MyServer, %{})
    GenServer.call(pid, :get)
  end

  defmodule MyServer do
    @moduledoc false
    use GenServer

    @impl true
    def init(state), do: {:ok, state}

    @impl true
    def handle_call(:get, _from, state), do: {:reply, state, state}

    @impl true
    def handle_call({:put, k, v}, _from, state), do: {:reply, :ok, Map.put(state, k, v)}

    @impl true
    def handle_cast({:inc, k}, state), do: {:noreply, Map.update(state, k, 1, &(&1 + 1))}

    @impl true
    def handle_info(_msg, state), do: {:noreply, state}
  end

  defmodule MySupervisor do
    @moduledoc false
    use Supervisor

    def start_link(arg) do
      Supervisor.start_link(__MODULE__, arg, name: __MODULE__)
    end

    @impl true
    def init(_arg) do
      children = [
        {EdgeCases.MyServer, %{}}
      ]

      Supervisor.init(children, strategy: :one_for_one)
    end
  end

  def agent_demo do
    {:ok, pid} = Agent.start_link(fn -> 0 end)
    Agent.update(pid, &(&1 + 1))
    val = Agent.get(pid, & &1)
    Agent.stop(pid)
    val
  end

  def task_demo do
    task = Task.async(fn -> 1 + 2 end)
    Task.await(task)
  end

  def task_async_stream(list) do
    list
    |> Task.async_stream(fn n -> n * 2 end, max_concurrency: 4)
    |> Enum.map(fn {:ok, v} -> v end)
  end

  def process_demo do
    pid = spawn(fn -> receive do msg -> {:got, msg} end end)
    send(pid, :hello)
    pid
  end

  def spawn_link_demo do
    spawn_link(fn -> :timer.sleep(10) end)
  end

  def spawn_monitor_demo do
    {pid, ref} = spawn_monitor(fn -> :ok end)

    receive do
      {:DOWN, ^ref, :process, ^pid, reason} -> {:done, reason}
    after
      1_000 -> :timeout
    end
  end

  def try_demo(x) do
    try do
      div(10, x)
    rescue
      ArithmeticError -> :divzero
      e in RuntimeError -> {:runtime, e.message}
    catch
      :throw, v -> {:throw, v}
      :exit, r -> {:exit, r}
    else
      n when n > 0 -> {:positive, n}
      n -> {:nonpositive, n}
    after
      :always_runs
    end
  end

  def throw_demo do
    try do
      Enum.each(1..100, fn n ->
        if n == 7, do: throw({:found, n})
      end)

      :not_found
    catch
      {:found, n} -> {:got, n}
    end
  end

  def raise_demo, do: raise(ArgumentError, message: "boom")

  def reraise_demo do
    try do
      raise "inner"
    rescue
      e -> reraise(e, __STACKTRACE__)
    end
  end

  def fibers_like_demo do
    fun = fn _ -> :crypto.strong_rand_bytes(8) end
    Enum.map(1..5, fun)
  end

  def weakmap_like do
    map = %{a: 1, b: 2}
    Enum.into(map, %{})
  end

  def first_class_demo do
    fns = [&String.upcase/1, &String.downcase/1, &String.reverse/1]
    Enum.map(fns, fn f -> f.("hello") end)
  end

  def conditional_compile do
    if function_exported?(:erlang, :system_info, 1) do
      :erlang.system_info(:otp_release)
    else
      :unknown
    end
  end

  def receive_demo do
    receive do
      {:hello, from} -> send(from, :hi)
      :stop -> :stopped
    after
      100 -> :timeout
    end
  end

  def selective_receive do
    receive do
      {:priority, p} -> {:p, p}
    after
      0 ->
        receive do
          other -> {:other, other}
        after
          100 -> :none
        end
    end
  end

  def map_match_deep(%{user: %{addr: %{city: city, zip: zip}}}) do
    {city, zip}
  end

  def map_match_deep(_), do: :no_match

  def function_capture_in_pipe(list) do
    list
    |> Enum.map(&Integer.to_string/1)
    |> Enum.map(&String.pad_leading(&1, 3, "0"))
  end

  def generator_with_filter(list) do
    for x <- list, y <- list, x < y, into: [], do: {x, y}
  end

  def into_struct_demo do
    %__MODULE__{id: 1, name: "alice", tags: [:admin]}
  end

  def update_struct(%__MODULE__{} = ec) do
    %{ec | name: String.upcase(ec.name), meta: Map.put(ec.meta, :updated, true)}
  end

  def access_demo(map) do
    map[:nested][:key]
  end

  def behaviour_user do
    defmodule UserGreeter do
      @moduledoc false
      use Greeter

      def greet(name), do: "Hi, " <> name
      def farewell(name), do: "Bye, " <> name
    end

    UserGreeter.hello("world")
  end
end
