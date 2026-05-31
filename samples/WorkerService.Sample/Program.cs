using PostQuantum.KeyManagement.Extensions.DependencyInjection;
using WorkerService.Sample;

HostApplicationBuilder builder = Host.CreateApplicationBuilder(args);

builder.Services.AddPostQuantumKeyManagement(options =>
{
    options.Passphrase = builder.Configuration["KeyManagement:Passphrase"]
        ?? throw new InvalidOperationException("KeyManagement:Passphrase is required.");
    options.WorkFactor = KekWorkFactor.Interactive;
    options.KeyringPath = builder.Configuration["KeyManagement:KeyringPath"] ?? "keyring.bin";
});

// Two hosted services so each concern is independent and individually observable.
builder.Services.AddHostedService<LivenessWorker>();
builder.Services.AddHostedService<RotationWorker>();

builder.Services.Configure<RotationOptions>(builder.Configuration.GetSection("KeyManagement:Rotation"));

IHost host = builder.Build();
await host.RunAsync();
