defmodule VulnCheck.Feeds.ArchiveTest do
  use ExUnit.Case, async: true

  alias VulnCheck.Feeds.Archive

  test "inflate/3 handles gzip and raw deflate and rejects corrupt or oversized data" do
    assert {:ok, "hello"} = Archive.inflate(:zlib.gzip("hello"), 31, 1024)
    assert {:error, {:invalid_compressed_data, _}} = Archive.inflate("not gzip", 31, 1024)

    assert {:error, {:archive_too_large, :uncompressed}} =
             Archive.inflate(:zlib.gzip("0123456789"), 31, 5)
  end

  test "zip_entry/2 decodes valid entries and rejects invalid or mismatched entries" do
    payload = String.duplicate("{\"id\":\"A\"}\n", 20)
    {:ok, {_, zip}} = :zip.create(~c"test.zip", [{~c"a.json", payload}], [:memory])
    {:ok, handle} = :zip.zip_open(zip, [:memory])
    {:ok, [_ | [entry]]} = :zip.zip_list_dir(handle)
    :ok = :zip.zip_close(handle)

    assert {:ok, ^payload} = Archive.zip_entry(zip, entry)
    assert {:error, :invalid_zip_entry} = Archive.zip_entry(zip, :not_an_entry)
    assert {:error, :invalid_zip_entry} = Archive.zip_entry("short", entry)

    {:ok, {_, stored_zip}} =
      :zip.create(~c"stored.zip", [{~c"a.json", "plain"}], [:memory, {:compress, []}])

    {:ok, h2} = :zip.zip_open(stored_zip, [:memory])
    {:ok, [_ | [stored_entry]]} = :zip.zip_list_dir(h2)
    :ok = :zip.zip_close(h2)
    assert {:ok, "plain"} = Archive.zip_entry(stored_zip, stored_entry)

    tampered = String.replace(stored_zip, "plain", "plaiX")
    assert {:error, :invalid_zip_entry} = Archive.zip_entry(tampered, stored_entry)

    # Data descriptor (bit 3 = 8) with and without signature, plus error paths
    body = "ok"
    crc = :erlang.crc32(body)
    sz = byte_size(body)

    file_info =
      {:file_info, sz, :regular, :read_write, {{2026, 1, 1}, {0, 0, 0}}, {{2026, 1, 1}, {0, 0, 0}},
       {{2026, 1, 1}, {0, 0, 0}}, 0, 0, 0, 0, 0, 0, 0}

    synth_entry = {:zip_file, ~c"x", file_info, ~c"", 0, sz}

    mk_hdr = fn flags, method, comp_sz, uncomp_sz, trailer ->
      <<0x04034B50::32-little, 20::16-little, flags::16-little, method::16-little, 0::32, 0::32,
        comp_sz::32-little, uncomp_sz::32-little, 1::16-little, 0::16-little, "x", body::binary,
        trailer::binary>>
    end

    with_sig =
      mk_hdr.(8, 0, sz, sz, <<0x08074B50::32-little, crc::32-little, sz::32-little, sz::32-little>>)

    assert {:ok, "ok"} = Archive.zip_entry(with_sig, synth_entry)

    no_sig = mk_hdr.(8, 0, sz, sz, <<crc::32-little, sz::32-little, sz::32-little>>)
    assert {:ok, "ok"} = Archive.zip_entry(no_sig, synth_entry)

    bad_desc = mk_hdr.(8, 0, sz, sz, <<"bad">>)
    assert {:error, :invalid_zip_descriptor} = Archive.zip_entry(bad_desc, synth_entry)

    bad_size = mk_hdr.(0, 0, sz + 1, sz, <<>>)
    assert {:error, :invalid_zip_size} = Archive.zip_entry(bad_size, synth_entry)

    bad_method = mk_hdr.(0, 99, sz, sz, <<>>)
    assert {:error, :unsupported_zip_entry} = Archive.zip_entry(bad_method, synth_entry)
  end
end
