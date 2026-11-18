defmodule VulnCheck.Feeds.Archive do
  @moduledoc false

  import Bitwise

  def inflate(data, window_bits, max_bytes) do
    stream = :zlib.open()

    try do
      :ok = :zlib.inflateInit(stream, window_bits)

      with {:ok, output} <- drain(stream, :zlib.safeInflate(stream, data), [], max_bytes),
           :ok <- :zlib.inflateEnd(stream) do
        {:ok, output}
      end
    catch
      :error, reason -> {:error, {:invalid_compressed_data, reason}}
    after
      :zlib.close(stream)
    end
  end

  defp drain(stream, {status, output}, chunks, left) when status in [:continue, :finished] do
    remaining = left - IO.iodata_length(output)

    cond do
      remaining < 0 -> {:error, {:archive_too_large, :uncompressed}}
      status == :finished -> {:ok, IO.iodata_to_binary(Enum.reverse([output | chunks]))}
      true -> drain(stream, :zlib.safeInflate(stream, []), [output | chunks], remaining)
    end
  end

  defp drain(_stream, _result, _chunks, _remaining), do: {:error, :unsupported_compression}

  # The directory is parsed by OTP. Inflate the entry separately so the
  # directory's declared size is an enforced ceiling for actual expansion.
  def zip_entry(zip, {:zip_file, _name, info, _comment, offset, compressed_size})
      when offset >= 0 and compressed_size >= 0 and offset < byte_size(zip) do
    expected = elem(info, 1)

    with <<0x04034B50::32-little, _version::16, flags::16-little, method::16-little, _timestamp::32,
           crc::32-little, local_compressed::32-little, local_size::32-little, name_size::16-little,
           extra_size::16-little, rest::binary>> <-
           binary_part(zip, offset, byte_size(zip) - offset),
         true <- (flags &&& 0x41) == 0,
         skip = name_size + extra_size,
         <<_::binary-size(^skip), compressed::binary-size(^compressed_size), trailer::binary>> <-
           rest,
         {:ok, checksum} <-
           checksum(flags, crc, local_compressed, local_size, trailer, {compressed_size, expected}),
         {:ok, body} <- decode_zip_entry(compressed, method, expected),
         true <- byte_size(body) == expected and :erlang.crc32(body) == checksum do
      {:ok, body}
    else
      {:error, _} = error -> error
      _ -> {:error, :invalid_zip_entry}
    end
  end

  def zip_entry(_zip, _entry), do: {:error, :invalid_zip_entry}

  defp checksum(flags, crc, compressed, size, _trailer, {compressed, size})
       when (flags &&& 8) == 0,
       do: {:ok, crc}

  defp checksum(flags, _crc, _compressed, _size, trailer, {compressed, size})
       when (flags &&& 8) != 0 do
    case trailer do
      <<0x08074B50::32-little, crc::32-little, ^compressed::32-little, ^size::32-little, _::binary>> ->
        {:ok, crc}

      <<crc::32-little, ^compressed::32-little, ^size::32-little, _::binary>> ->
        {:ok, crc}

      _ ->
        {:error, :invalid_zip_descriptor}
    end
  end

  defp checksum(_flags, _crc, _compressed, _size, _trailer, _expected),
    do: {:error, :invalid_zip_size}

  defp decode_zip_entry(bytes, 0, size) when byte_size(bytes) == size, do: {:ok, bytes}
  defp decode_zip_entry(bytes, 8, size), do: inflate(bytes, -15, size)
  defp decode_zip_entry(_bytes, _method, _size), do: {:error, :unsupported_zip_entry}
end
