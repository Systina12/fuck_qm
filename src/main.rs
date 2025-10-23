use anyhow::{Context, Result};
use frida::{Frida, Message};
use serde_json::json;
use std::env::args_os;
use std::ffi::OsString;
use std::io::{self, Write};
use std::path::PathBuf;
use std::sync::LazyLock;

static FRIDA: LazyLock<Frida> = LazyLock::new(|| unsafe { Frida::obtain() });

fn main() {
    if let Err(e) = run() {
        eprintln!("错误: {:#}", e);
        wait_for_enter("按回车键退出...");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    // 只接受第一个命令行参数（Windows 拖放到 exe 时会把文件路径当作参数）
    let mut args = args_os().skip(1);
    let maybe_dropped: Option<OsString> = args.next();

    // 如果没有传入参数，打印并等待（按你的新要求）
    if maybe_dropped.is_none() {
        println!("没有传入");
        wait_for_enter("按回车键退出...");
        return Ok(());
    }

    // 以下为处理传入单个文件的逻辑
    let dropped_path: PathBuf = PathBuf::from(maybe_dropped.unwrap());
    println!("[*] 收到拖放文件: {}", dropped_path.display());

    if !dropped_path.exists() {
        anyhow::bail!("文件不存在: {}", dropped_path.display());
    }
    if !dropped_path.is_file() {
        anyhow::bail!("不是文件: {}", dropped_path.display());
    }

    // 初始化 Frida、设备、并附加 QQMusic（保持原逻辑）
    let device_manager = frida::DeviceManager::obtain(&FRIDA);
    let device = device_manager.get_local_device()?;
    println!("[*] Frida version: {}", Frida::version());
    println!("[*] Device name: {}", device.get_name());
    let qq_music_process = device
        .enumerate_processes()
        .into_iter()
        .find(|x| x.get_name().to_ascii_lowercase().contains("qqmusic"))
        .context("请先启动QQ音乐")?;

    let session = device.attach(qq_music_process.get_pid())?;
    let mut script_option = frida::ScriptOption::default();
    let js = include_str!(".././hook_qq_music.js");
    // 注意这里 script 是可变的
    let mut script = session.create_script(js, &mut script_option)?;
    script.handle_message(Handler)?;
    script.load()?;

    // 目标目录就是该文件所在目录
    let parent_dir = dropped_path
        .parent()
        .map(PathBuf::from)
        .context("无法确定文件所在目录")?;

    // 传入可变引用
    process_single_file(&mut script, &dropped_path, &parent_dir)?;

    Ok(())
}

/// 处理单个文件：根据扩展名决定是否处理、调用 JS decrypt，输出到 same_dir
/// 注意：script 现在是 &mut frida::Script
fn process_single_file(script: &mut frida::Script, path: &PathBuf, same_dir: &PathBuf) -> Result<()> {
    // 检查扩展名并映射
    let extension_opt = path
        .extension()
        .and_then(|s| s.to_str())
        .map(|s| s.to_ascii_lowercase());
    let new_ext = match extension_opt.as_deref() {
        Some("mflac") => "flac",
        Some("mgg") => "ogg",
        _ => {
            anyhow::bail!(
                "不支持的文件扩展名: {:?}",
                path.extension().and_then(|s| s.to_str())
            );
        }
    };

    // new file name（只文件名部分），并在 same_dir 下构造目标路径
    let file_stem = path.file_stem().and_then(|s| s.to_str()).context("无法读取文件名")?;
    let new_file_name = format!("{}.{}", file_stem, new_ext);
    let new_file_path = same_dir.join(&new_file_name);

    if new_file_path.exists() {
        println!("[*] 目标文件已存在: {} 跳过处理", new_file_path.display());
        return Ok(());
    }

    // 以 new_file_name 的 md5 作为临时文件名（和原逻辑一致），放在 same_dir
    let md5_file_name = format!("{:x}", md5::compute(new_file_name.as_str()));
    let new_md5_path = same_dir.join(md5_file_name);

    println!(
        "[*] 调用脚本解密: {} -> {} (临时: {})",
        path.display(),
        new_file_path.display(),
        new_md5_path.display()
    );

    // 调用 JS 导出的 decrypt(path, out_path)
    // 现在 script 是 &mut，可以调用需要可变借用的方法
    script.exports.call(
        "decrypt",
        Some(json!([path.display().to_string(), new_md5_path.display().to_string()])),
    )?;

    // 重命名临时文件到目标文件
    std::fs::rename(&new_md5_path, &new_file_path).context(format!(
        "无法重命名文件: {} -> {}",
        new_md5_path.display(),
        new_file_path.display()
    ))?;

    println!("[*] 处理完成: {}", new_file_path.display());
    Ok(())
}

/// 简单的消息处理器：打印 message（保持原样）
struct Handler;
impl frida::ScriptHandler for Handler {
    fn on_message(&mut self, message: &Message, _data: Option<Vec<u8>>) {
        println!("- {:?}", message);
    }
}

/// 等待用户按回车并显示提示（仅在错误或无参数时使用）
fn wait_for_enter(prompt: &str) {
    let _ = io::stdout().flush();
    println!("{}", prompt);
    let mut s = String::new();
    let _ = io::stdin().read_line(&mut s);
}
