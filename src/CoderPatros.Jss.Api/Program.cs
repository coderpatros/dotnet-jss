using CoderPatros.Jss.Api.Endpoints;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

builder.WebHost.ConfigureKestrel(o => o.Limits.MaxRequestBodySize = 10 * 1024 * 1024); // 10 MB

var app = builder.Build();

app.UseSwagger();
app.UseSwaggerUI();

app.MapKeyEndpoints();
app.MapSignEndpoints();
app.MapVerifyEndpoints();

app.MapGet("/", () => Results.Redirect("/swagger")).ExcludeFromDescription();

app.Run();

public partial class Program { }
