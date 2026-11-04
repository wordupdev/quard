<?php
/** One document-root .htaccess file; private backups, hash checks and atomic replacement. */
namespace Quard;

defined( 'ABSPATH' ) || exit;

class ManagedFile {
	private $root;
	private $backups;

	public function __construct( $root, $backups ) {
		$root = rtrim( $root, '/' );
		if ( ! $root || realpath( $root ) !== $root || is_link( $root ) || ! is_dir( $root ) ) {
			throw new \RuntimeException( 'Document root must be an unambiguous real directory.' );
		}
		$this->root = $root;
		$this->backups = rtrim( $backups, '/' );
		if ( ! $this->backups || 0 === strpos( $this->backups . '/', $root . '/' ) || is_link( $this->backups ) || realpath( dirname( $this->backups ) ) !== dirname( $this->backups ) ) {
			throw new \RuntimeException( 'Backups must use a real private directory outside the document root.' );
		}
	}

	public function path() { return $this->root . '/.htaccess'; }

	public function snapshot() {
		clearstatcache();
		if ( is_link( $this->root ) || realpath( $this->root ) !== $this->root || ! is_dir( $this->root ) ) { throw new \RuntimeException( 'Document root changed or became a symlink.' ); }
		$path = $this->path();
		$st = lstat( $this->root );
		if ( ! is_writable( $this->root ) || ( $st['mode'] & 0002 ) ) {
			throw new \RuntimeException( 'Document root is not safely writable.' );
		}
		if ( is_link( $path ) ) {
			throw new \RuntimeException( 'Refusing a symlinked .htaccess.' );
		}
		$exists = file_exists( $path );
		$meta = $exists ? lstat( $path ) : null;
		if ( $exists && ( ! is_file( $path ) || 1 !== $meta['nlink'] || ! is_readable( $path ) || ! is_writable( $path ) || ! ( $meta['mode'] & 0222 ) || ( $meta['mode'] & 0002 ) || $meta['size'] > 1048576 ) ) {
			throw new \RuntimeException( '.htaccess must be a readable/writable regular file with one link and safe size/mode.' );
		}
		if ( $exists && function_exists( 'posix_geteuid' ) && $meta['uid'] !== posix_geteuid() ) {
			throw new \RuntimeException( 'File ownership cannot be preserved by this PHP user. Use manual export.' );
		}
		$data = $exists ? file_get_contents( $path ) : '';
		if ( false === $data ) { throw new \RuntimeException( 'Cannot read .htaccess.' ); }
		return array( 'exists' => $exists, 'bytes' => $data, 'hash' => hash( 'sha256', $data ), 'meta' => $meta, 'root_inode' => $st['ino'] );
	}

	/** Strict markers; never infer ownership from a filename or delete unrelated blocks. */
	public static function region( $bytes ) {
		preg_match_all( '/^[^\r\n]*#[ \t]*(?:BEGIN|END)[ \t]+Quard\b[^\r\n]*\r?$/mi', $bytes, $all, PREG_OFFSET_CAPTURE );
		if ( ! $all[0] ) { return null; }
		if ( 2 !== count( $all[0] ) || ! preg_match( '/\A# BEGIN Quard\r?\z/', $all[0][0][0] ) || ! preg_match( '/\A# END Quard\r?\z/', $all[0][1][0] ) ) {
			throw new \RuntimeException( 'Conflicting, duplicated or malformed Quard markers. Reconcile manually.' );
		}
		$start = $all[0][0][1];
		$end = $all[0][1][1] + strlen( $all[0][1][0] );
		if ( isset( $bytes[ $end ] ) && "\n" === $bytes[ $end ] ) { ++$end; }
		foreach ( array( 'WordPress', 'LITESPEED', 'LSCACHE' ) as $owner ) {
			preg_match_all( '/^# (BEGIN|END) ' . $owner . '\r?$/mi', $bytes, $markers, PREG_OFFSET_CAPTURE );
			$inside = false;
			foreach ( $markers[0] as $i => $marker ) {
				if ( $marker[1] >= $end ) { break; }
				if ( $marker[1] >= $start || ( $inside && $marker[1] >= $start ) ) {
					throw new \RuntimeException( 'Quard is nested in another managed block.' );
				}
				$inside = 'BEGIN' === strtoupper( $markers[1][ $i ][0] );
			}
			if ( $inside ) { throw new \RuntimeException( 'Quard is nested in another managed block.' ); }
		}
		return array( 'start' => $start, 'end' => $end, 'block' => substr( $bytes, $start, $end - $start ) );
	}

	public function plan( $block, $owned_hash = '', $remove = false ) {
		$s = $this->snapshot();
		$r = self::region( $s['bytes'] );
		if ( $owned_hash && ! $r ) { throw new \RuntimeException( 'Previously owned Quard markers are missing. Reconcile manually.' ); }
		if ( $r && ( ! $owned_hash || ! hash_equals( $owned_hash, hash( 'sha256', $r['block'] ) ) ) ) {
			throw new \RuntimeException( 'Existing Quard block is unowned or changed. Reconcile manually.' );
		}
		preg_match( '/\r\n|\n|\r/', $s['bytes'], $match );
		$eol = $match ? $match[0] : "\n";
		$block = $remove ? '' : str_replace( "\n", $eol, str_replace( "\r\n", "\n", $block ) );
		if ( ! $remove ) {
			$generated = self::region( $block );
			if ( ! $generated || 0 !== $generated['start'] || strlen( $block ) !== $generated['end'] ) { throw new \RuntimeException( 'Generated block is invalid.' ); }
		}
		$after = $r ? substr( $s['bytes'], 0, $r['start'] ) . $block . substr( $s['bytes'], $r['end'] ) : $block . $s['bytes'];
		if ( strlen( $after ) > 1048576 ) { throw new \RuntimeException( 'Resulting .htaccess exceeds the managed size limit. Use manual review.' ); }
		return array( 'snapshot' => $s, 'after' => $after, 'block_hash' => $remove ? '' : hash( 'sha256', $block ), 'kind' => $after === $s['bytes'] ? 'Idempotent reapply' : ( $remove ? 'Remove Quard block' : ( $r ? 'Update' : 'First install' ) ) );
	}

	private function private_dir() {
		if ( realpath( dirname( $this->backups ) ) !== dirname( $this->backups ) ) { throw new \RuntimeException( 'Backup parent changed or became ambiguous.' ); }
		if ( ! is_dir( $this->backups ) && ! mkdir( $this->backups, 0700 ) ) { throw new \RuntimeException( 'Cannot create private backup directory.' ); }
		$st = lstat( $this->backups );
		if ( is_link( $this->backups ) || realpath( $this->backups ) !== $this->backups || ( $st['mode'] & 0077 ) || ! is_writable( $this->backups ) || ( function_exists( 'posix_geteuid' ) && $st['uid'] !== posix_geteuid() ) ) {
			throw new \RuntimeException( 'Backup directory must be private, owned and writable.' );
		}
	}

	/** Kept protected so interruption can be exercised without a runtime fault-injection control. */
	protected function atomic_write( array $before, $bytes ) {
		$temp = tempnam( $this->root, '.quard-' );
		if ( false === $temp ) { throw new \RuntimeException( 'Cannot stage file.' ); }
		try {
			$handle = fopen( $temp, 'wb' );
			if ( ! $handle ) { throw new \RuntimeException( 'Cannot open staged file.' ); }
			try {
				$offset = 0;
				while ( $offset < strlen( $bytes ) ) {
					$n = fwrite( $handle, substr( $bytes, $offset ) );
					if ( false === $n || 0 === $n ) { throw new \RuntimeException( 'Incomplete staged write.' ); }
					$offset += $n;
				}
				if ( ! fflush( $handle ) ) { throw new \RuntimeException( 'Cannot flush staged file.' ); }
				if ( function_exists( 'fsync' ) ) { fsync( $handle ); }
			} finally { fclose( $handle ); }
			if ( $before['exists'] && fileowner( $temp ) !== $before['meta']['uid'] ) { throw new \RuntimeException( 'Cannot preserve file ownership; use manual export.' ); }
			$mode = $before['exists'] ? ( $before['meta']['mode'] & 0777 ) : 0644;
			if ( ! chmod( $temp, $mode ) ) { throw new \RuntimeException( 'Cannot preserve file mode.' ); }
			if ( $before['exists'] && filegroup( $temp ) !== $before['meta']['gid'] && ! chgrp( $temp, $before['meta']['gid'] ) ) { throw new \RuntimeException( 'Cannot preserve file group.' ); }
			$this->unchanged( $before );
			if ( ! rename( $temp, $this->path() ) ) { throw new \RuntimeException( 'Atomic replacement failed.' ); }
		} finally { if ( file_exists( $temp ) ) { unlink( $temp ); } }
	}

	private function unchanged( array $expected ) {
		$now = $this->snapshot();
		if ( $now['exists'] !== $expected['exists'] || $now['hash'] !== $expected['hash'] || $now['root_inode'] !== $expected['root_inode'] || ( $now['exists'] && array_intersect_key( $now['meta'], array_flip( array( 'ino', 'dev', 'uid', 'gid', 'mode' ) ) ) !== array_intersect_key( $expected['meta'], array_flip( array( 'ino', 'dev', 'uid', 'gid', 'mode' ) ) ) ) ) {
			throw new \RuntimeException( 'Concurrent file/metadata edit detected; nothing was overwritten.' );
		}
	}

	public function commit( array $plan, callable $verify ) {
		$this->private_dir();
		$lock_path = $this->backups . '/lock';
		if ( is_link( $lock_path ) ) { throw new \RuntimeException( 'Unsafe lock file.' ); }
		$lock = fopen( $lock_path, 'c' );
		if ( ! $lock || ! flock( $lock, LOCK_EX | LOCK_NB ) ) { if ( $lock ) { fclose( $lock ); } throw new \RuntimeException( 'Another Quard operation holds the lock.' ); }
		try {
			$this->unchanged( $plan['snapshot'] );
			if ( $plan['after'] === $plan['snapshot']['bytes'] && empty( $plan['restore_absent'] ) ) { return array( 'changed' => false, 'verified' => (bool) $verify(), 'backup' => '' ); }
			$backup = $this->backups . '/' . bin2hex( random_bytes( 16 ) ) . '.json';
			$record = array( 'path' => $this->path(), 'before' => base64_encode( $plan['snapshot']['bytes'] ), 'existed' => $plan['snapshot']['exists'], 'mode' => $plan['snapshot']['exists'] ? ( $plan['snapshot']['meta']['mode'] & 0777 ) : 0644, 'after_hash' => hash( 'sha256', $plan['after'] ) );
			$h = fopen( $backup, 'x' );
			if ( ! $h ) { throw new \RuntimeException( 'Cannot create recovery record.' ); }
			chmod( $backup, 0600 );
			$data = json_encode( $record );
			$n = fwrite( $h, $data ); fflush( $h ); if ( function_exists( 'fsync' ) ) { fsync( $h ); } fclose( $h );
			if ( $n !== strlen( $data ) ) { throw new \RuntimeException( 'Recovery record incomplete; file was not changed.' ); }
			$this->atomic_write( $plan['snapshot'], $plan['after'] );
			$written = $this->snapshot();
			try { $passed = (bool) $verify(); } catch ( \Throwable $e ) { $passed = false; }
			$this->unchanged( $written );
			if ( ! $passed ) {
				$current = $this->snapshot();
				if ( $current['hash'] !== $record['after_hash'] ) { throw new \RuntimeException( 'Smoke test failed and concurrent edit prevents automatic recovery. Use the private backup.' ); }
				if ( $record['existed'] ) { $this->atomic_write( $current, base64_decode( $record['before'], true ) ); } else { $this->unchanged( $current ); unlink( $this->path() ); }
				throw new \RuntimeException( 'HTTP verification failed; exact previous file restored.' );
			}
			if ( ! empty( $plan['restore_absent'] ) ) {
				$current = $this->snapshot();
				if ( $current['hash'] !== $record['after_hash'] ) { throw new \RuntimeException( 'Concurrent edit prevents restoring original absence.' ); }
				$this->unchanged( $current );
				unlink( $this->path() );
			}
			return array( 'changed' => true, 'verified' => true, 'backup' => basename( $backup ), 'after_hash' => $record['after_hash'], 'block_hash' => $plan['block_hash'] );
		} finally { flock( $lock, LOCK_UN ); fclose( $lock ); }
	}

	public function restore_plan( $name ) {
		$this->private_dir();
		if ( ! preg_match( '/\A[a-f0-9]{32}\.json\z/D', $name ) || is_link( $this->backups . '/' . $name ) ) { throw new \RuntimeException( 'Invalid recovery record.' ); }
		$record = json_decode( file_get_contents( $this->backups . '/' . $name ), true );
		$s = $this->snapshot();
		if ( ! is_array( $record ) || $record['path'] !== $this->path() || $record['after_hash'] !== $s['hash'] ) { throw new \RuntimeException( 'Recovery snapshot no longer matches the current file.' ); }
		$before = base64_decode( $record['before'], true );
		if ( false === $before ) { throw new \RuntimeException( 'Invalid backup bytes.' ); }
		$r = self::region( $before );
		return array( 'snapshot' => $s, 'after' => $before, 'block_hash' => $r ? hash( 'sha256', $r['block'] ) : '', 'kind' => 'Restore previous configuration', 'restore_absent' => ! $record['existed'] );
	}
}
